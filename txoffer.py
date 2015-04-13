# -*- coding: utf-8 -*-

from pathtools.patterns import match_any_paths

from twisted.application import internet, service, strports
from twisted.internet import reactor, tcp
from twisted.internet.address import IPv4Address
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.internet.task import LoopingCall
from twisted.protocols.policies import ThrottlingFactory
from twisted.protocols.tls import _PullToPush
from twisted.python import log, logfile
from twisted.python.filepath import FilePath
from twisted.web.resource import EncodingResourceWrapper, ErrorPage, NoResource, Resource
from twisted.web.server import GzipEncoderFactory, NOT_DONE_YET, Site
from twisted.web.static import File
from twisted.web.template import Element, flatten, renderer, XMLString, XMLFile
from twisted.words.protocols.irc import DccSendProtocol, DccSendFactory, fileSize, IRCClient

from watchdog.events import PatternMatchingEventHandler, LoggingEventHandler
from watchdog.observers import Observer

import binascii, collections, datetime, fnmatch, json, math, os, re, socket, struct, threading, types, urllib2, yaml

# Utility functions
def timedeltaToHuman(td, short=False):
    fmt_str = "in {}" if td.total_seconds() >= 0 else "{} ago"
    td = abs(td)

    hours = td.seconds // 3600
    minutes = (td.seconds // 60) % 60
    seconds = td.seconds % 60

    if short:
        day, hour, minute, second = "dhms"
    else:
        day = " day, " if td.days == 1 else " days, "
        hour = " hour, " if hours == 1 else " hours, "
        minute = " minute, " if minutes == 1 else " minutes and "
        second = " second" if seconds == 1 else " seconds"

    if td.days:
        time_str = "{:,d}{}{:d}{}{:d}{}{:d}{}".format(td.days, day, hours, hour, minutes, minute, seconds, second)
    elif hours:
        time_str = "{:d}{}{:d}{}{:d}{}".format(hours, hour, minutes, minute, seconds, second)
    elif minutes:
        time_str = "{:d}{}{:d} {}".format(minutes, minute, seconds, second)
    else:
        time_str = "{:d}{}".format(seconds, second)

    return fmt_str.format(time_str)

def bytesToHuman(num):
    for x in ['B','KB','MB','GB']:
        if num < 1000.0:
            return "{:3.1f}{}".format(num, x)
        num /= 1000.0
    return "{:3.1f}{}".format(num, 'TB')

# Detect file creation
class EventHandler(PatternMatchingEventHandler):
    def dispatch(self, event):
        if event.src_path is None:
            event._src_path = "/dev/null"
        PatternMatchingEventHandler.dispatch(self, event)

    def on_created(self, event):
        self.reactor.callFromThread(self.function, os.path.abspath(event.src_path))

    def on_modified(self, event):
        self.reactor.callFromThread(self.function, os.path.abspath(event.src_path))

    def on_moved(self, event):
        self.reactor.callFromThread(self.function, os.path.abspath(event.dest_path))

    def on_deleted(self, event):
        pass

# Connect to irc
class FancyDccSendProtocol(DccSendProtocol):
    blocksize = 256 * 1024 # 256 KB/block

    def __init__(self, file):
        DccSendProtocol.__init__(self, file)
        self.buf = collections.deque()
        self.transferred = 0
        self.paused = False
        self.checker = LoopingCall(self.reset)
        self.checker.start(1)

    def connectionMade(self):
        # If throttled, send block size to throttle / phi
        # rounded down to the nearest KB
        if self.factory.master.config["throttle"] is not None:
            kb = float(self.factory.master.config["throttle"]) / (1024 * 1.6180339887498948)
            self.blocksize = math.floor(kb) * 1024

        self.bytesSent = self.factory.resume
        self.file.seek(self.bytesSent)
        DccSendProtocol.connectionMade(self)
        self.factory.address.stopListening()
        self.factory.checker.cancel()

    def register(self, length):
        self.transferred += length
        self.factory.download["downloaded"] += length

        if self.factory.limit is not None and self.transferred > self.factory.limit:
            throttleTime = (float(self.transferred) / self.factory.limit) - 1.0
            self.throttle(throttleTime)
            self.unthrottleID = reactor.callLater(throttleTime, self.unthrottle)

    def reset(self):
        self.transferred = 0

    def throttle(self, t):
        #log.msg("Throttling writes on %s for %0.2f seconds" % (self, t))
        self.paused = True

    def unthrottle(self):
        self.unthrottleID = None
        #log.msg("Stopped throttling writes on %s" % self)
        self.paused = False
        self.sendBlock()

    def dataReceived(self, data):
        self.buf.extend(data)

        while len(self.buf) >= 4:
            data = "".join([self.buf.popleft(), self.buf.popleft(), self.buf.popleft(), self.buf.popleft()])
            bytesShesGot = struct.unpack("!I", data)[0]

            if bytesShesGot == (self.bytesSent & 0xFFFFFFFF):
                self.sendBlock()
            elif bytesShesGot > self.bytesSent:
                self.transport.loseConnection()

    def sendBlock(self):
        if self.paused:
            return

        block = self.file.read(self.blocksize)
        if block:
            self.transport.write(block)
            self.bytesSent = self.bytesSent + len(block)
            self.register(len(block))
        else:
            # Nothing more to send, transfer complete.
            self.transport.loseConnection()
            self.completed = 1

    def connectionLost(self, reason):
        DccSendProtocol.connectionLost(self, reason)
        del self.factory.master.downloads[self.factory.download["recipient"]][self.factory.download["pack"]]
        self.factory.master.checkQueue()
        self.checker.stop()

class QuietPort(tcp.Port):
    # Exactly the same as tcp.Port but without log.msg
    def startListening(self):
        """Create and bind my socket, and begin listening on it.

        This is called on unserialization, and must be called after creating a
        server to begin listening on the specified port.
        """
        if self._preexistingSocket is None:
            # Create a new socket and make it listen
            try:
                skt = self.createInternetSocket()
                if self.addressFamily == socket.AF_INET6:
                    addr = _resolveIPv6(self.interface, self.port)
                else:
                    addr = (self.interface, self.port)
                skt.bind(addr)
            except socket.error as le:
                raise CannotListenError(self.interface, self.port, le)
            skt.listen(self.backlog)
        else:
            # Re-use the externally specified socket
            skt = self._preexistingSocket
            self._preexistingSocket = None
            # Avoid shutting it down at the end.
            self._socketShutdownMethod = None

        # Make sure that if we listened on port 0, we update that to
        # reflect what the OS actually assigned us.
        self._realPortNumber = skt.getsockname()[1]

        # The order of the next 5 lines is kind of bizarre.  If no one
        # can explain it, perhaps we should re-arrange them.
        self.factory.doStart()
        self.connected = True
        self.socket = skt
        self.fileno = self.socket.fileno
        self.numberAccepts = 100

        self.startReading()

    # Get rid of shutdown logging as well
    def _logConnectionLostMsg(self):
        pass

class Bot(IRCClient):
    lineRate = 0.400
    sourceURL = "https://github.com/Fugiman/txoffer"
    versionEnv = "Twisted-Python"
    versionName = "txoffer (Custom Bot)"
    versionNum = "0.1"

    def connectionMade(self):
        self.nickname = self.factory.nickname
        IRCClient.connectionMade(self)
        self.factory.connection = self

    def connectionLost(self, reason=None):
        self.factory.connection = None

    def signedOn(self):
        if self.factory.password:
            self.msg("NickServ","IDENTIFY {}".format(self.factory.password))
        self.factory.resetDelay()
        for channel in self.factory.channels:
            self.join(channel)

    def send(self, hostmask, number):
        user, _, _ = hostmask.partition("!")
        name = os.path.basename(self.factory.master.packs[number])

        if hostmask not in self.factory.master.downloads:
            self.factory.master.downloads[hostmask] = {}

        if number in self.factory.master.downloads[hostmask]:
            return

        if not os.path.isfile(self.factory.master.packs[number]):
            return self.notice(user, "Pack #{:d} \"{}\" is unavailable".format(number, name))

        size = os.path.getsize(self.factory.master.packs[number])
        if not size:
            return self.notice(user, "Pack is empty")

        self.factory.master.downloads[hostmask][number] = {
            "pack": number,
            "recipient": hostmask,
            "filename": name,
            "filesize": size,
            "downloaded": 0,
            "started": datetime.datetime.utcnow()
        }

        if self.factory.master.config["log_requests"]:
            log.msg("Serving: {} - {}".format(hostmask, name), system=self.factory.host)
        self.notice(user, "Sending #{:d} - {}".format(number, name))

        factory = DccSendFactory(self.factory.master.packs[number])
        address = QuietPort(0, factory, 1)

        factory.master = self.factory.master
        factory.noisy = False
        factory.protocol = FancyDccSendProtocol
        factory.resume = 0
        factory.limit = self.factory.master.config["throttle"]
        factory.download = self.factory.master.downloads[hostmask][number]
        factory.address = address
        factory.stopped = False

        address.startListening()

        host = self.factory.master.public_ip
        if "." in host: # Convert to unsigned int
            host = reduce(lambda a,b: a<<8 | b, map(int, host.split(".")))
        port = address.getHost().port

        args = ["SEND", '"{}"'.format(name), host, port]
        if size is not None:
            args.append(size)

        self.factory.master.downloads[hostmask][number]["factory"] = factory
        self.factory.master.downloads[hostmask][number]["address"] = address
        self.factory.master.downloads[hostmask][number]["port"] = port

        self.ctcpMakeQuery(user, [("DCC", " ".join([str(x) for x in args]))])
        factory.checker = reactor.callLater(self.factory.master.config["timeout"], self.stop, factory)

    def stop(self, factory):
        del self.factory.master.downloads[factory.download["recipient"]][factory.download["pack"]]
        factory.address.stopListening()
        factory.stopped = True
        self.factory.master.checkQueue()

    def ctcpUnknownQuery(self, hostmask, channel, tag, data):
        if tag.lower() == "xdcc":
            self.privmsg(hostmask, channel, "{} {}".format(tag, data))
        else:
            IRCClient.ctcpUnknownQuery(self, hostmask, channel, tag, data)

    def privmsg(self, hostmask, channel, message):
        user, _, _ = hostmask.partition("!")
        message = message.strip().lower()

        if (channel == self.nickname and message.startswith("xdcc ")) or (self.nickname.lower() in message and "xdcc " in message):
            _, _, message = message.partition("xdcc ")
            subcommand, _, args = message.partition(" ")
            if subcommand == "send" or subcommand == "get":
                number, _, _ = args.partition(" ")

                if number == "list":
                    message = "!list"

                else:
                    try:
                        number = int(number.strip("#"))
                    except ValueError:
                        pattern = "*".join([''] + args.split(" ") + [''])
                        names = [name for name in self.factory.master.packs.values() if fnmatch.fnmatch(name.lower(), pattern)]
                        names.reverse() # Newest first

                        if names and len(names) == 1:
                            number = self.factory.master.pack_lookup[names[0]]
                        elif names:
                            return self.notice(user, "\"{}\" is not specific enough to find a single pack. Use !list or !find.".format(args))
                        else:
                            return self.notice(user, "Invalid pack number ({})".format(number))

                    if number not in self.factory.master.packs:
                        return self.notice(user, "Invalid pack number ({:d})".format(number))

                    if not os.path.isfile(self.factory.master.packs[number]):
                        return self.notice(user, "Pack #{:d} was deleted".format(number))

                    try:
                        position = list(self.factory.master.queue).index((self, hostmask, number)) + 1
                        self.notice(user, "You have already requested to download this pack, and are #{:,d} in the queue".format(position))
                    except ValueError:
                        self.factory.master.queue.append((self, hostmask, number))
                        self.factory.master.checkQueue()
                        if self.factory.master.queue and self.factory.master.queue[-1] == (self, hostmask, number):
                            self.notice(user, "You are #{:,d} in the queue".format(len(self.factory.master.queue)))

                    return

            elif subcommand == "search":
                message = "@find {}".format(args)
                # Let @find handler take care of it

            elif subcommand == "list":
                message = "!list"
                # Let !list handler take care of it

            elif subcommand == "batch":
                numbers, _, _ = args.partition(" ")
                numbers = numbers.split(",")
                numbers = filter(lambda n: re.match("\d+(-\d+)?$", n), numbers)
                numbers = [n for a in numbers for n in range(int(a.partition("-")[0]), int(a.partition("-")[2] if a.partition("-")[1] else a.partition("-")[0]) + 1)]
                for n in numbers:
                    self.privmsg(hostmask, channel, "xdcc send {}".format(n))
                return

            elif subcommand == "remove" or subcommand == "clear":
                numbers, _, _ = args.partition(" ")
                numbers = numbers.split(",")
                numbers = filter(lambda n: re.match("\d+(-\d+)?$", n), numbers)
                numbers = [n for a in numbers for n in range(int(a.partition("-")[0]), int(a.partition("-")[2] if a.partition("-")[1] else a.partition("-")[0]) + 1)]

                for place, data in enumerate(list(self.factory.master.queue)):
                    if data[1] == hostmask and (not numbers or data[2] in numbers):
                        self.factory.master.queue.remove(data)
                        self.notice(user, "Removed pack #{:d} from queue. You were #{:,d}".format(data[2], place + 1))

            elif subcommand == "queue":
                pending = []
                for place, data in enumerate(list(self.factory.master.queue)):
                    if data[1] == hostmask:
                        pending.append("#{:,d}: {}".format(place + 1, os.path.basename(self.factory.master.packs[data[2]])))

                if pending:
                    return self.notice(user, "Queued packs: {}".format(", ".join(pending)))

                return self.notice(user, "No packs queued")

        if message == "!list":
            send_max = "{:,d}".format(self.factory.master.config["global_concurrent"]) if self.factory.master.config["global_concurrent"] is not None else self.factory.master.config["infinity"].encode("utf8")
            queue_max = self.factory.master.config["infinity"].encode("utf8")
            self.notice(user, "Packlist: {} || Packs: {:,d} || Sending: {:,d} / {} || Queued: {:,d} / {}".format(self.factory.master.public_address, len(self.factory.master.packs), sum(map(len, self.factory.master.downloads.values())), send_max, len(self.factory.master.queue), queue_max))
            return

        if message.startswith("@find ") or message.startswith("!find "):
            _, _, args = message.partition(" ")
            pattern = "*".join([''] + args.split(" ") + [''])
            names = [name for name in self.factory.master.packs.values() if fnmatch.fnmatch(name.lower(), pattern)]
            names.reverse() # Newest first
            pack_list = ", ".join(["#{:d} {}".format(self.factory.master.pack_lookup[name], os.path.basename(name)) for name in names][:self.factory.master.config["search_limit"]])

            if pack_list:
                self.notice(user, "Packs: {}".format(pack_list))

            return

        if message == "!new":
            pack_list = ", ".join(["#{:d} {}".format(number, os.path.basename(name)) for number, name in reversed(self.factory.master.packs.items())][:self.factory.master.config["search_limit"]])

            if pack_list:
                self.notice(user, "Recent: {}".format(pack_list))

            return

    def dccDoResume(self, hostmask, file, port, resumePos):
        user, _, _ = hostmask.partition("!")

        if hostmask not in self.factory.master.downloads:
            return

        numbers = [n for f, n in self.factory.master.pack_lookup.items() if os.path.basename(f) == file]
        dls = [dl for dl in self.factory.master.downloads[hostmask].values() if dl["pack"] in numbers and dl["port"] == port]

        if not dls or len(dls) > 1:
            return

        factory = dls[0]["factory"]
        factory.resume = resumePos
        factory.checker.reset(self.factory.master.config["timeout"])
        self.dccAcceptResume(user, '"{}"'.format(file), port, resumePos)

class BotFactory(ReconnectingClientFactory):
    maxDelay = 5 * 60
    protocol = Bot
    noisy = False

    def __init__(self, nickname, password, channels):
        self.nickname = nickname
        self.password = password
        self.channels = channels
        self.connection = None

# Offer web interface
class ThrottledRequest(object):
    def __init__(self, factory, wrappedRequest):
        self.factory = factory
        self.wrappedRequest = wrappedRequest

    def write(self, data):
        self.factory.register(len(data))
        self.wrappedRequest.write(data)

    def registerProducer(self, producer, streaming):
        if not streaming:
            producer = _PullToPush(producer, self)
            producer.startStreaming()

        self.producer = producer
        self.streaming = streaming
        self.wrappedRequest.registerProducer(producer, True)

    def unregisterProducer(self):
        if hasattr(self, "producer"):
            if not self.streaming:
                self.producer.stopStreaming()
            del self.producer
        self.wrappedRequest.unregisterProducer()

    def throttle(self):
        if hasattr(self, "producer") and self.producer:
            self.producer.pauseProducing()

    def unthrottle(self):
        if hasattr(self, "producer") and self.producer:
            self.producer.resumeProducing()

    def __getattr__(self, name):
        return getattr(self.wrappedRequest, name)

class ThrottledResource(Resource):
    isLeaf = False

    def __init__(self, wrappedResource, download, limit=None):
        Resource.__init__(self)
        self.wrappedResource = wrappedResource
        self.download = download
        self.limit = limit
        self.transferred = 0
        self.resetID = LoopingCall(self.reset)
        self.unthrottleID = None
        self.requests = []

    def render(self, request):
        if not self.requests and self.limit is not None:
            self.resetID.start(1)

        request = ThrottledRequest(self, request)
        self.requests.append(request)
        request.notifyFinish().addBoth(self.done, request)

        return self.wrappedResource.render(request)

    def getChildWithDefault(self, path, request):
        request.postpath.insert(0, request.prepath.pop())
        return self.wrappedResource

    def done(self, result, request):
        self.requests.remove(request)

        if not self.requests and self.resetID.running:
            self.resetID.stop()

    def register(self, length):
        self.transferred += length
        self.download["downloaded"] += length

        if self.limit is not None and self.transferred > self.limit:
            throttleTime = (float(self.transferred) / self.limit)
            self.throttle(throttleTime)
            self.unthrottleID = reactor.callLater(throttleTime, self.unthrottle)

    def reset(self):
        self.transferred = 0

    def throttle(self, t):
        #log.msg("Throttling writes on %s for %0.2f seconds" % (self, t))
        for r in self.requests:
            r.throttle()

    def unthrottle(self):
        self.unthrottleID = None
        #log.msg("Stopped throttling writes on %s" % self)
        for r in self.requests:
            r.unthrottle()

class IndexElement(Element):
    loader = XMLFile(FilePath('web/index.html'))

    def __init__(self, master):
        self.master = master

    @renderer
    def pack(self, request, tag):
        for number, name in reversed(self.master.packs.items()):
	    size = self.master.pack_size[number]
	    if size == 0:
	        continue
            if self.master.config["web_function"] == "ddl":
                link = "/pack/{:d}/{}".format(number, os.path.basename(name))
            else:
                link = "javascript:ToClipboard('/msg {} XDCC SEND {:d}')".format(self.master.config["irc"][0]["nickname"] if self.master.config["irc"] else "BOTNICK", number)
#            size = bytesToHuman(self.master.pack_size[number])
            yield tag.clone().fillSlots(link=link, size=bytesToHuman(size), number="#{:d}".format(number), name=os.path.basename(name))

class StatusElement(Element):
    loader = XMLFile(FilePath('web/status.html'))

    def __init__(self, master):
        self.master = master

    @renderer
    def download_count(self, request, tag):
        return tag("{:,d}".format(sum(map(len, self.master.downloads.values()))))

    @renderer
    def download_max(self, request, tag):
        return tag("{:,d}".format(self.master.config["global_concurrent"]) if self.master.config["global_concurrent"] is not None else self.master.config["infinity"])

    @renderer
    def download(self, request, tag):
        now = datetime.datetime.utcnow()
        for dl in sorted([d for u in self.master.downloads.values() for d in u.values()], key=lambda dl: dl["started"]):
            slots = {
                "started": timedeltaToHuman(dl["started"] - now, short=True),
                "recipient": dl["recipient"].partition("!")[0],
                "filename": dl["filename"],
                "downloaded": bytesToHuman(dl["downloaded"]),
                "filesize": bytesToHuman(dl["filesize"]),
                "percentage": "{:.2%}".format(float(dl["downloaded"]) / dl["filesize"])
            }
            yield tag.clone().fillSlots(**slots)

    @renderer
    def queue_count(self, request, tag):
        return tag("{:,d}".format(len(self.master.queue)))

    @renderer
    def queue_max(self, request, tag):
        return tag(self.master.config["infinity"])

    @renderer
    def queue(self, request, tag):
        for place, data in enumerate(list(self.master.queue)):
            slots = {
                "spot": "{:,d}".format(place + 1),
                "recipient": data[1].partition("!")[0],
                "filename": os.path.basename(self.master.packs[data[2]])
            }
            yield tag.clone().fillSlots(**slots)

class QueueElement(Element):
    loader = XMLFile(FilePath('web/queue.html'))

    def __init__(self, master, filename, position):
        self.master = master
        self._filename = str(filename)
        self._position = str(position)

    @renderer
    def filename(self, request, tag):
        return tag(self._filename)

    @renderer
    def position(self, request, tag):
        return tag(self._position)

    @renderer
    def refresh(self, request, tag):
        return tag(str(self.master.config["web_refresh"]))

class IndexResource(Resource):
    def getChild(self, path, request):
        return EncodingResourceWrapper(self, [GzipEncoderFactory()])

    def render_GET(self, request):
        request.write("<!doctype html>\n")

        d = flatten(request, IndexElement(self.master), request.write)
        d.addCallback(lambda _: request.finish())
        d.addErrback(request.processingFailed)

        return NOT_DONE_YET

class RobotResource(Resource):
    isLeaf = True

    def render_GET(self, request):
        return "User-agent: *\nDisallow: /"

class PacksTxtResource(Resource):
    isLeaf = True

    def render_GET(self, request):
        request.setHeader('content-type', 'text/plain')
        for number, name in self.master.packs.items():
            size = self.master.pack_size[number]
	    if size == 0:
	        continue
            name = os.path.basename(name)
            request.write("#%s [%s]\t%s\n" % (number, bytesToHuman(size), name))
        request.finish()
        return NOT_DONE_YET

class StatusResource(Resource):
    isLeaf = True

    def render_GET(self, request):
        request.write("<!doctype html>\n")

        d = flatten(request, StatusElement(self.master), request.write)
        d.addCallback(lambda _: request.finish())
        d.addErrback(request.processingFailed)

        return NOT_DONE_YET

class ListResource(Resource):
    isLeaf = True

    def render_GET(self, request):
        with open('web/list.js') as f:
            return f.read()

class PackResource(NoResource):
    def __init__(self):
        NoResource.__init__(self, "No pack number specified")
        self.brief = "No Such Pack"
        self.types = collections.namedtuple("Pack_Types", ["ERROR", "REDIRECT", "QUEUE"])._make(range(3))
        self.type = self.types.ERROR

    def getChild(self, path, request):
        request.postpath = []

        if self.master.config["web_function"] != "ddl":
            self.brief = "DDL Disabled"
            self.detail = "The owner of this txoffer instance has chosen to disable DDL. Use XDCC or pester them to turn it back on."
            return self

        try:
            number = int(path)
        except:
            self.brief = "Invalid Pack Number"
            self.detail = "Given pack number \"{}\" is not a valid integer".format(path)
            return self

        if number not in self.master.packs:
            self.brief = "No Such Pack"
            self.detail = "Could not find a pack with number \"{:d}\".".format(number)
            return self

        if not os.path.isfile(self.master.packs[number]):
            self.brief = "Pack #{:d} Deleted".format(number)
            self.detail = "{} no longer exists.".format(os.path.basename(self.master.packs[number]))
            return self

        if self.master.config["proxy_header"] is not None:
            host = request.getHeader(self.master.config["proxy_header"])
        else:
            host = request.getClientIP()

        if host in self.factory.authorized and number in self.factory.authorized[host]:
            if self.master.config["log_requests"]:
                log.msg("Serving: {} - {}".format(host, os.path.basename(self.master.packs[number])), system="WEB")
            self.factory.authorized[host].remove(number)
            request.notifyFinish().addBoth(self.factory.done, host, number)
            r = EncodingResourceWrapper(File(self.master.packs[number]), [GzipEncoderFactory()])
            return ThrottledResource(r, self.master.downloads[host][number], limit=self.master.config["throttle"])

        elif host in self.master.downloads and number in self.master.downloads[host]:
            request.redirect("/")
            self.type = self.types.REDIRECT
            return self

        else:
            try:
                position = list(self.master.queue).index((self.factory, host, number)) + 1
                element = QueueElement(self.master, os.path.basename(self.master.packs[number]), position)
                request.write("<!doctype html>\n")

                d = flatten(request, element, request.write)
                d.addCallback(lambda _: request.finish())
                d.addErrback(request.processingFailed)

                self.type = self.types.QUEUE
                return self

            except ValueError:
                self.master.queue.append((self.factory, host, number))
                self.master.checkQueue()
                request.redirect("/pack/{:d}/{}".format(number, os.path.basename(self.master.packs[number])))
                self.type = self.types.REDIRECT
                return self

    def render(self, request):
        if self.type == self.types.REDIRECT:
            return ""
        elif self.type == self.types.QUEUE:
            return NOT_DONE_YET
        else:
            return NoResource.render(self, request)

class Web(Site):
    def __init__(self, master):
        self.authorized = {}

        index = IndexResource()
        robot = RobotResource()
        listjs = ListResource()
        status = StatusResource()
        pack = PackResource()
        packs = PacksTxtResource()

        index.factory = robot.factory = listjs.factory = status.factory = pack.factory = self
        self.master = index.master = robot.master = listjs.master = status.master = pack.master = packs.master = master

        Site.__init__(self, EncodingResourceWrapper(index, [GzipEncoderFactory()]))
        index.putChild("robots.txt", robot) # No reason to bother gzipping this
        index.putChild("list.js", EncodingResourceWrapper(listjs, [GzipEncoderFactory()]))
        index.putChild("status", EncodingResourceWrapper(status, [GzipEncoderFactory()]))
        index.putChild("pack", EncodingResourceWrapper(pack, [GzipEncoderFactory()]))
        index.putChild("packs.txt", EncodingResourceWrapper(packs, [GzipEncoderFactory()]))

    def send(self, host, number):
        if host not in self.master.downloads:
            self.master.downloads[host] = {}

        self.master.downloads[host][number] = {
            "pack": number,
            "recipient": host,
            "filename": os.path.basename(self.master.packs[number]),
            "filesize": os.path.getsize(self.master.packs[number]),
            "downloaded": 0,
            "started": datetime.datetime.utcnow()
        }

        if host not in self.authorized:
            self.authorized[host] = []
        self.authorized[host].append(number)

        reactor.callLater(self.master.config["timeout"], self.check, host, number)

    def check(self, host, number):
        if number in self.authorized[host]:
            self.authorized[host].remove(number)
            self.done(None, host, number)

    def done(self, result, host, number):
        del self.master.downloads[host][number]
        self.master.checkQueue()

ErrorPage.template = """<!doctype html>
<html>
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
        <title>%(code)s - %(brief)s</title>
        <link rel="stylesheet" href="//fonts.googleapis.com/css?family=Ubuntu:400,700">
        <style>
            html {
                color: #333;
                font-family: Ubuntu, sans-serif;
                font-size: 16px;
                line-height: 34px;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <h1>%(brief)s</h1>
        <p>%(detail)s</p>
    </body>
</html>"""

# Master service
class ConfigException(Exception):
    pass

class Master(service.MultiService):
    def __init__(self):
        service.MultiService.__init__(self)

        with open("txoffer.yaml", "r") as f:
            self.config = yaml.safe_load(f)
        self.validateConfig(self.config)

    def privilegedStartService(self):
        pass

    def _addrIsUsable (self, addr):
        ip = addr[4][0]
        return not ip.startswith("127.0.0.1") and not ip.startswith("192.168")

    def startService(self):
        self.updatePublicAddress()

        self.web = Web(self)
        self.web.noisy = False
        self.web.log = lambda request: None

        self.packs = {}
        self.pack_size = {}
        self.pack_lookup = {}
        self.pack_number = 1

        self.bots = []
        self.downloads = {}
        self.queue = collections.deque()

        self.loadPacklist()
        self.checkPacklist()

        self.observer = None
        self.watch_scheduler = {}
        self.internal_scheduler = {}

        self.startObserver()

        for conn in self.config["irc"]:
            factory = BotFactory(conn["nickname"], conn["password"] if "password" in conn else None, conn["channels"])
            factory.master = self
            factory.host = conn["host"]
            srvc = internet.TCPClient(conn["host"], conn["port"], factory)
            srvc.setName("{}:{:d}".format(conn["host"], conn["port"]))
            srvc.factory = factory
            srvc.setServiceParent(self)
            self.bots.append(factory)

        if self.config["web_function"] != "nothing":
            for path in self.config["endpoints"]:
                srvc = strports.service(path, self.web)
                srvc.setName("web_{}".format(path))
                srvc.setServiceParent(self)

        return service.MultiService.startService(self)

    def stopService(self):
        self.stopObserver()

        for timer in self.watch_scheduler.values():
            timer.cancel()

        for timer in self.internal_scheduler.values():
            timer.cancel()

        return service.MultiService.stopService(self)

    def updatePublicAddress(self):
        if self.config["address"] is not None:
            self.public_host = self.config["address"]
            self.public_ip = [addr[4][0] for addr in socket.getaddrinfo(self.public_host, None) if self._addrIsUsable(addr)][0]
        else:
            try:
                conn = urllib2.urlopen("http://ifconfig.me/all.json", timeout=3)
                data = json.loads(conn.read())
                self.raw_ip, self.raw_host = data["ip_addr"], data["remote_host"]
            except:
                log.err("Couldn't fetch remote IP and hostname")
                self.raw_host = socket.getfqdn()
                ips = [addr[4][0] for addr in socket.getaddrinfo(self.raw_host, None) if self._addrIsUsable(addr)]
                self.raw_ip = ips[0] if ips else "127.0.0.1"

            self.public_host = self.raw_host
            self.public_ip = self.raw_ip

        tcp = map(lambda p: int(p.split(":")[1]), filter(lambda p: p.startswith("tcp"), self.config["endpoints"]))
        if self.config["port"]:
            self.public_port = self.config["port"]
        elif tcp and 80 not in tcp:
            self.public_port = tcp[0]
        else:
            self.public_port = 80

        self.public_address = "http://{}:{:d}/".format(self.public_host, self.public_port) if self.public_port != 80 else "http://{}/".format(self.public_host)

    def updateConfig(self):
        with open("txoffer.yaml", "r") as f:
            config = yaml.safe_load(f)

        # Validate the new config
        try:
            self.validateConfig(config)
        except ConfigException as e:
            log.msg("Couldn't reload config: {!s}".format(e))
            return

        # Restart observer if needed
        include_diff = (config["include"] is not None and
                        self.config["include"] is not None and
                        (set(config["include"]) != set(self.config["include"])) or
                        (config["include"] is not None and self.config["include"] is None) or
                        (config["include"] is None and self.config["include"] is not None))
        exclude_diff = (config["exclude"] is not None and
                        self.config["exclude"] is not None and
                        (set(config["exclude"]) != set(self.config["exclude"])) or
                        (config["exclude"] is not None and self.config["exclude"] is None) or
                        (config["exclude"] is None and self.config["exclude"] is not None))
        if config["watch_directory"] != self.config["watch_directory"] or include_diff or exclude_diff:
            self.stopObserver()
            self.startObserver()

        # Find what servers need joining, parting or modifying
        new_ircs = dict([("{}:{:d}".format(d["host"], d["port"]), d) for d in config["irc"]])
        old_ircs = dict([("{}:{:d}".format(d["host"], d["port"]), d) for d in self.config["irc"]])

        # If the host hasn't changed, then it just needs modifying
        for address in (set(new_ircs.keys()) & set(old_ircs.keys())):
            ndata = new_ircs[address]
            odata = old_ircs[address]
            srvc = self.getServiceNamed(address)

            if ndata["nickname"] != odata["nickname"]:
                srvc.factory.nickname = ndata["nickname"]
                if srvc.factory.connection:
                    srvc.factory.connection.setNick(ndata["nickname"])

            password = ndata["password"] if "password" in ndata else None
            if password != srvc.factory.password:
                srvc.factory.password = password
                if srvc.factory.connection:
                    srvc.factory.connection.msg("NickServ","IDENTIFY {}".format(password))

            new_chans, old_chans = set(ndata["channels"]), set(odata["channels"])
            if new_chans != old_chans:
                srvc.factory.channels = ndata["channels"]
                if srvc.factory.connection:
                    for chan in (old_chans - new_chans):
                        srvc.factory.connection.leave(chan)
                    for chan in (new_chans - old_chans):
                        srvc.factory.connection.join(chan)

        # A new host needs a new service
        for address in (set(new_ircs.keys()) - set(old_ircs.keys())):
            data = new_ircs[address]
            factory = BotFactory(data["nickname"], data["password"] if "password" in data else None, data["channels"])
            factory.master = self
            factory.host = data["host"]
            srvc = internet.TCPClient(data["host"], data["port"], factory)
            srvc.setName(address)
            srvc.factory = factory
            srvc.setServiceParent(self)
            self.bots.append(factory)

        # A lost host needs disconnecting
        for address in (set(old_ircs.keys()) - set(new_ircs.keys())):
            srvc = self.getServiceNamed(address)
            srvc.stopService()
            self.bots.remove(srvc.factory)

        # Have the endpoints changed?
        old_paths, new_paths = set(self.config["endpoints"]), set(config["endpoints"])

        # Hack in shutting down the webserver if web_function == nothing
        if self.config["web_function"] == "nothing":
            old_paths = set()

        if config["web_function"] == "nothing":
            new_paths = set()

        # Stop old paths
        for path in (old_paths - new_paths):
            srvc = self.getServiceNamed("web_{}".format(path))
            srvc.stopService()

        # Start new paths
        for path in (new_paths - old_paths):
            srvc = strports.service(path, self.web)
            srvc.setName("web_{}".format(path))
            srvc.setServiceParent(self)

        self.config = config
        log.msg("Reloaded config")

    def validateConfig(self, config):
        keys = ["watch_directory", "crc_validation", "include", "exclude", "irc",
                "address", "port", "proxy_header", "endpoints", "global_concurrent",
                "ip_concurrent", "throttle", "timeout", "web_refresh", "infinity",
                "search_limit", "log_requests"]
        for key in keys:
            if key not in config:
                raise ConfigException("Missing config option \"{}\"".format(key))

        if not isinstance(config["watch_directory"], basestring):
            raise ConfigException("watch_directory must be a string")

        if not isinstance(config["crc_validation"], bool):
            raise ConfigException("crc_validation must be a boolean")

        if not isinstance(config["include"], list) and config["include"] is not None:
            raise ConfigException("include must be a list or null")

        if config["include"] is not None:
            for value in config["include"]:
                if not isinstance(value, basestring):
                    raise ConfigException("include must be a list of strings")

        if not isinstance(config["exclude"], list) and config["exclude"] is not None:
            raise ConfigException("exclude must be a list or null")

        if config["exclude"] is not None:
            for value in config["exclude"]:
                if not isinstance(value, basestring):
                    raise ConfigException("exclude must be a list of strings")

        if not isinstance(config["irc"], list):
            raise ConfigException("irc must be a list")

        keys = ["host", "port", "nickname", "channels"]
        for value in config["irc"]:
            if not isinstance(value, dict):
                raise ConfigException("irc must be a list of objects")

            for key in keys:
                if key not in value:
                    raise ConfigException("irc values must contain a value for \"{}\"".format(key))

            if not isinstance(value["host"], basestring):
                raise ConfigException("irc host must be a string")

            if not isinstance(value["port"], int):
                raise ConfigException("irc port must be an int")

            if not isinstance(value["nickname"], basestring):
                raise ConfigException("irc nickname must be a string")

            if "password" in value:
                if not isinstance(value["password"], basestring):
                    raise ConfigException("irc password must be a string")

            if not isinstance(value["channels"], list):
                raise ConfigException("irc channels must be a list")

            for v in value["channels"]:
                if not isinstance(v, basestring):
                    raise ConfigException("irc channels must be a list of strings")

        if max([0] + collections.Counter(["{}:{:d}".format(d["host"], d["port"]) for d in config["irc"]]).values()) > 1:
            raise ConfigException("irc host+port must be unique")

        if not isinstance(config["web_function"], basestring):
            raise ConfigException("web_function must be a string")

        if config["web_function"] not in ["ddl", "xdcc", "nothing"]:
            raise ConfigException("web_function must be 'ddl', 'xdcc' or 'nothing'")

        if not isinstance(config["address"], basestring) and config["address"] is not None:
            raise ConfigException("address must be a string or null")

        if not isinstance(config["port"], int) and config["port"] is not None:
            raise ConfigException("port must be an int or null")

        if not isinstance(config["proxy_header"], basestring) and config["proxy_header"] is not None:
            raise ConfigException("proxy_header must be a string or null")

        if not isinstance(config["endpoints"], list):
            raise ConfigException("endpoints must be a list")

        for value in config["endpoints"]:
            if not isinstance(value, basestring):
                raise ConfigException("endpoints must be a list of ints")

        if max([0] + collections.Counter(config["endpoints"]).values()) > 1:
            raise ConfigException("endpoints must be unique")

        if not isinstance(config["global_concurrent"], int) and config["global_concurrent"] is not None:
            raise ConfigException("global_concurrent must be an int or null")

        if not isinstance(config["ip_concurrent"], int) and config["ip_concurrent"] is not None:
            raise ConfigException("ip_concurrent must be an int or null")

        if not isinstance(config["throttle"], int) and config["throttle"] is not None:
            raise ConfigException("throttle must be an int or null")

        if not isinstance(config["timeout"], int):
            raise ConfigException("timeout must be an int")

        if not isinstance(config["web_refresh"], int):
            raise ConfigException("web_refresh must be an int")

        if config["web_refresh"] > config["timeout"] - 5:
            raise ConfigException("web_refresh must be at least 5 seconds shorter than timeout")

        if not isinstance(config["infinity"], basestring):
            raise ConfigException("infinity must be a string")

        if not isinstance(config["search_limit"], int):
            raise ConfigException("search_limit must be an int")

        if not isinstance(config["log_requests"], bool):
            raise ConfigException("log_requests must be a boolean")

    def announce(self, pack, name):
        for bot in self.bots:
            if bot.connection is not None:
                for channel in bot.channels:
                    channel, _, password = channel.partition(" ")
                    ddl = " or at {}pack/{:d}".format(self.public_address, pack) if self.config["web_function"] == "ddl" else ""
                    bot.connection.msg(channel, 'Pack #{0:d} added: {1} - Get it with "/msg {2} XDCC SEND {0:d}"{3}'.format(pack, name, bot.nickname, ddl))

    def addPack(self, filename):
        if filename in self.pack_lookup:
            return

        if self.config["crc_validation"]:
            match = re.search("\[([0-9a-fA-F]{8})\]", filename)
            if not match:
                log.msg("No CRC found in potential pack: {}".format(filename))
                return

            expected_crc = match.group(1).upper()
            with open(filename, "rb") as f:
                actual_crc = "{:08X}".format(binascii.crc32(f.read()) & 0xFFFFFFFF)

            if expected_crc != actual_crc:
                log.msg("CRC mismatch in potential pack. Expected = {}, Actual = {}, File = {}".format(expected_crc, actual_crc, filename))
                return

        self.packs[self.pack_number] = filename
        try:
            self.pack_size[self.pack_number] = os.path.getsize(filename)
        except:
            self.pack_size[self.pack_number] = 0
        self.pack_lookup[filename] = self.pack_number

        with open("txoffer.packlist", "a") as f:
            f.write(filename + "\n")

        log.msg("Added pack #{:d}: {}".format(self.pack_number, filename))
        self.announce(self.pack_number, os.path.basename(filename))

        self.pack_number += 1

    def checkQueue(self):
        for conn, name, number in list(self.queue):
            if self.config["global_concurrent"] is not None and sum(map(len, self.downloads.values())) >= self.config["global_concurrent"]:
                break

            if name in self.downloads and self.config["ip_concurrent"] is not None and len(self.downloads[name]) >= self.config["ip_concurrent"]:
                continue

            conn.send(name, number)
            self.queue.remove((conn, name, number))

    def loadPacklist(self):
        try:
            with open("txoffer.packlist", "r") as f:
                for index, path in enumerate(f.readlines()):
                    path = path.strip()
                    if not path:
                        continue
                    number = index + 1
                    self.packs[number] = path
                    try:
                        self.pack_size[number] = os.path.getsize(path)
                    except:
                        self.pack_size[number] = 0
                    self.pack_lookup[path] = number
                self.pack_number = len(self.packs) + 1
        except IOError:
            pass

    def checkPacklist(self):
        folder_list = [self.config["watch_directory"]]
        file_list = []
        while folder_list:
            new_folder_list = []
            for folder in folder_list:
                for root, folders, files in os.walk(folder):
                    new_folder_list.extend([os.path.join(root, f) for f in folders])
                    file_list.extend([os.path.abspath(os.path.join(root, f)) for f in files])
            folder_list = new_folder_list

        file_list = filter(lambda filename: filename not in self.pack_lookup and
                      match_any_paths([filename], included_patterns=self.config["include"],
                        excluded_patterns=self.config["exclude"], case_sensitive=False), file_list)
        file_list.sort(key=lambda path: os.path.basename(path))

        for f in file_list:
            self.addPack(f)

    def startObserver(self):
        watch_dir_handler = EventHandler(self.config["include"], self.config["exclude"], True, False)
        watch_dir_handler.reactor = reactor
        watch_dir_handler.function = self.eventOccurred

        self_dir_handler = EventHandler(["*txoffer.yaml"], None, False, False)
        self_dir_handler.reactor = reactor
        self_dir_handler.function = self.internalFileChanged

        self.observer = Observer()
        self.observer.schedule(watch_dir_handler, path=os.path.abspath(self.config["watch_directory"]), recursive=True)
        self.observer.schedule(self_dir_handler, path=".", recursive=False)
        self.observer.start()

    def stopObserver(self):
        if self.observer is not None:
            self.observer.stop()
        self.observer = None

    def eventOccurred(self, path):
        if not path.startswith(os.path.abspath(self.config["watch_directory"])):
            return

        if path in self.watch_scheduler:
            self.watch_scheduler[path].reset(10)
        else:
            self.watch_scheduler[path] = reactor.callLater(10, self.eventFinished, path)

    def eventFinished(self, path):
        del self.watch_scheduler[path]
        self.addPack(path)

    def internalFileChanged(self, path):
        if not path.startswith(os.path.abspath(".")):
            return

        if path in self.internal_scheduler:
            self.internal_scheduler[path].reset(10)
        else:
            self.internal_scheduler[path] = reactor.callLater(10, self.internalFileFinished, path)

    def internalFileFinished(self, path):
        del self.internal_scheduler[path]

        if path == os.path.abspath("./txoffer.yaml"):
            self.updateConfig()

# Launch the party
application = service.Application("txoffer")
applog = logfile.DailyLogFile("txoffer.log", ".")
application.setComponent(log.ILogObserver, log.FileLogObserver(applog).emit)
Master().setServiceParent(application)