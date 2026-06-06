"""Lexicon Normalizer — token analysis without replacement.

Provides the ``LexiconNormalizer`` class for detecting rare tokens,
UUIDs, code identifiers, hashes, emails, and long-form identifiers
in text. All detection methods are available as analysis tools.

``sanitize_text()`` is a pass-through — no placeholder substitution
or text modification is performed. The dedicated redaction plugin
handles replacement.

This plugin does not register any hooks or monkey-patch any API
calls. It is a pure library import.
"""

from __future__ import annotations

import re
from typing import Dict, Final, List, Set

_SAFE_ACRONYMS: Final[Set[str]] = {
    "API", "APIs", "ASCII", "AWS", "BIOS", "CLI", "CPU", "CSS",
    "CSV", "DMA", "DNS", "DOM", "DPI", "DSL", "DSOs", "DTO",
    "DTOs", "ELF", "FIFO", "FTP", "GIL", "GPU", "GUI", "HDMI",
    "HTML", "HTTP", "HTTPS", "I2C", "IANA", "ICMP", "IDE",
    "IETF", "IGMP", "IIS", "IMAP", "IoT", "IP", "IPC", "IRQ",
    "ISA", "ISR", "JSON", "JVM", "LIFO", "LLM", "LLMs", "LVM",
    "MAC", "MMIO", "MMU", "MVC", "MVP", "MVVM", "NaN", "NAS",
    "NIC", "NLP", "NN", "NPU", "OOP", "OS", "PCI", "PDF",
    "PHP", "PID", "POP3", "PSU", "QEMU", "RAID", "RAM", "REST",
    "RISC", "ROM", "RPC", "RPM", "RTOS", "RTT", "SATA", "SCSI",
    "SDK", "SDKs", "SLA", "SLI", "SMTP", "SNMP", "SOC", "SPI",
    "SQL", "SRAM", "SSD", "SSH", "SSL", "STDIN", "STDOUT",
    "SVG", "SWOT", "TCP", "TLS", "TTL", "TTS", "UART", "UDP",
    "UI", "UML", "UPS", "URI", "URL", "URN", "USB", "UTF",
    "UUID", "UUIDs", "VLAN", "VM", "VPN", "VRAM", "WAN", "WASM",
    "WYSIWYG", "XML", "XOR", "YAML", "YML",
}

_NEVER_NORMALISE: Final[Set[str]] = {
    "the", "this", "that", "these", "those", "a", "an", "and",
    "or", "but", "if", "else", "elif", "for", "while", "do",
    "done", "in", "on", "at", "by", "to", "from", "with",
    "without", "of", "not", "is", "are", "was", "were", "be",
    "been", "being", "have", "has", "had", "having", "do", "does",
    "did", "doing", "will", "would", "shall", "should", "may",
    "might", "must", "can", "could", "need", "dare", "ought",
    "used", "use", "using", "get", "gets", "got", "gotten",
    "make", "makes", "made", "set", "sets", "setting", "let",
    "lets", "letting", "put", "puts", "putting", "take", "takes",
    "took", "taken", "go", "goes", "went", "gone", "going",
    "come", "comes", "came", "coming", "see", "sees", "saw",
    "seen", "know", "knows", "knew", "known", "think", "thinks",
    "thought", "want", "wants", "wanted", "give", "gives",
    "gave", "given", "find", "finds", "found", "tell", "tells",
    "told", "say", "says", "said", "work", "works", "worked",
    "working", "seem", "seems", "seemed", "feel", "feels",
    "felt", "try", "tries", "tried", "leave", "leaves", "left",
    "call", "calls", "called", "calling", "keep", "keeps",
    "kept", "keeping", "start", "starts", "started", "starting",
    "help", "helps", "helped", "helping", "show", "shows",
    "showed", "shown", "hear", "hears", "heard", "play",
    "plays", "played", "playing", "run", "runs", "ran",
    "move", "moves", "moved", "moving", "live", "lives",
    "lived", "living", "believe", "believes", "believed",
    "bring", "brings", "brought", "happen", "happens",
    "happened", "happening", "write", "writes", "wrote",
    "written", "writing", "provide", "provides", "provided",
    "providing", "sit", "sits", "sat", "stand", "stands",
    "stood", "lose", "loses", "lost", "pay", "pays", "paid",
    "meet", "meets", "met", "include", "includes", "included",
    "including", "continue", "continues", "continued", "continue",
    "hold", "holds", "held", "expect", "expects", "expected",
    "expecting", "lead", "leads", "led", "learn", "learns",
    "learned", "learning", "change", "changes", "changed",
    "changing", "build", "builds", "built", "building",
    "read", "reads", "reading", "follow", "follows", "followed",
    "following", "support", "supports", "supported", "supporting",
    "understand", "understands", "understood", "understanding",
    "develop", "develops", "developed", "developing",
    "require", "requires", "required", "requiring",
    "report", "reports", "reported", "reporting",
    "apply", "applies", "applied", "applying",
    "appear", "appears", "appeared", "appearing",
    "achieve", "achieves", "achieved", "achieving",
    "choose", "chooses", "chose", "chosen", "choosing",
    "speak", "speaks", "spoke", "spoken", "speaking",
    "spend", "spends", "spent", "spending",
    "send", "sends", "sent", "sending",
    "sleep", "sleeps", "slept", "sleeping",
    "drive", "drives", "drove", "driven", "driving",
    "break", "breaks", "broke", "broken", "breaking",
    "draw", "draws", "drew", "drawn", "drawing",
    "eat", "eats", "ate", "eaten", "eating",
    "fall", "falls", "fell", "fallen", "falling",
    "feed", "feeds", "fed", "feeding",
    "fight", "fights", "fought", "fighting",
    "fly", "flies", "flew", "flown", "flying",
    "forget", "forgets", "forgot", "forgotten", "forgetting",
    "grow", "grows", "grew", "grown", "growing",
    "hide", "hides", "hid", "hidden", "hiding",
    "hit", "hits", "hitting",
    "hurt", "hurts", "hurting",
    "lay", "lays", "laid", "laying",
    "lie", "lies", "lay", "lain", "lying",
    "light", "lights", "lit", "lighting",
    "mean", "means", "meant", "meaning",
    "prove", "proves", "proved", "proven", "proving",
    "raise", "raises", "raised", "raising",
    "rise", "rises", "rose", "risen", "rising",
    "seek", "seeks", "sought", "seeking",
    "sell", "sells", "sold", "selling",
    "shoot", "shoots", "shot", "shooting",
    "shut", "shuts", "shutting",
    "sing", "sings", "sang", "sung", "singing",
    "slide", "slides", "slid", "sliding",
    "teach", "teaches", "taught", "teaching",
    "throw", "throws", "threw", "thrown", "throwing",
    "wear", "wears", "wore", "worn", "wearing",
    "win", "wins", "won", "winning",
    "wind", "winds", "wound", "winding",
    "withdraw", "withdraws", "withdrew", "withdrawn",
    "withdrawing",
}

_COMMON_ENGLISH: Set[str] = {
    "time", "year", "people", "way", "day", "man", "woman",
    "child", "world", "life", "hand", "part", "place", "case",
    "week", "company", "system", "program", "question", "work",
    "government", "number", "night", "point", "home", "water",
    "room", "mother", "area", "money", "story", "fact", "month",
    "lot", "right", "study", "book", "eye", "job", "word",
    "business", "issue", "side", "kind", "head", "house", "service",
    "friend", "father", "power", "hour", "game", "line", "end",
    "member", "law", "car", "city", "community", "name", "president",
    "team", "minute", "idea", "kid", "body", "information", "back",
    "parent", "face", "others", "level", "office", "door", "health",
    "person", "art", "war", "history", "party", "result", "change",
    "morning", "reason", "research", "girl", "guy", "moment",
    "air", "teacher", "force", "education", "class",
    "age", "industry", "cause", "nature", "road", "doctor",
    "student", "data", "science", "process", "resource",
    "language", "computer", "performance", "knowledge",
    "power", "quality", "attention", "security",
    "activity", "population", "product", "practice",
    "control", "effect", "value", "opportunity", "example",
    "course", "state", "country", "group", "order", "plan",
    "action", "policy", "position", "care", "list", "record",
    "paper", "space", "field", "report", "design", "form",
    "model", "type", "rate", "source", "code", "file",
    "image", "sound", "video", "site", "user", "client",
    "server", "tool", "map", "view", "link", "node",
    "framework", "platform", "feature", "version", "release",
    "update", "patch", "fix", "config", "configs",
    "setup", "build", "script", "function", "variable",
    "module", "package", "library", "class", "object", "method",
    "property", "attribute", "argument", "parameter", "value",
    "type", "instance", "interface", "protocol", "standard",
    "format", "style", "option", "mode", "level", "range",
    "limit", "total", "score", "test", "spec", "specs",
    "check", "step", "phase", "stage", "task", "job",
    "role", "rule", "goal", "target", "path", "route",
    "direction", "measure", "length", "width", "height",
    "depth", "distance", "speed", "weight", "volume",
    "color", "colour", "size", "shape", "position",
    "location", "address", "city", "state", "country",
    "region", "zone", "area", "section", "part",
    "component", "element", "item", "piece", "unit",
    "page", "topic", "subject",
    "title", "name", "label", "tag", "keyword",
    "term", "phrase", "sentence", "paragraph", "text",
    "content", "description", "summary", "detail",
    "folder", "directory", "path",
    "kind", "sort", "category",
    "set", "collection", "array", "list", "queue",
    "stack", "tree", "graph", "map", "table",
    "row", "column", "cell", "field", "record",
    "entry", "item", "element", "member", "node",
    "root", "leaf", "branch", "child", "parent",
    "sibling", "peer", "partner", "owner", "creator",
    "author", "editor", "viewer", "reader", "writer",
    "listener", "handler", "manager", "controller",
    "director", "leader", "head", "chief", "owner",
    "admin", "administrator", "operator",
    "developer", "engineer", "designer", "analyst",
    "architect", "consultant", "advisor", "assistant",
    "coordinator", "supervisor", "trainer", "instructor",
    "professor", "lecturer", "speaker",
    "journalist", "reporter",
    "publisher", "producer",
    "executive", "officer", "worker",
    "employee", "staff",
    "volunteer", "partner", "stakeholder",
    "customer", "consumer", "visitor",
    "guest", "audience", "spectator", "observer",
    "witness", "expert", "specialist", "professional",
    "master", "pioneer", "innovator",
    "supplier", "vendor", "provider", "distributor",
    "retailer", "wholesaler", "manufacturer",
    "contractor", "subcontractor",
    "agency", "bureau", "department", "division",
    "branch", "office", "unit",
    "committee", "board", "council", "panel",
    "commission", "taskforce",
    "goal", "objective", "mission", "vision", "purpose",
    "aim", "outcome", "result", "output",
    "deliverable", "product", "service", "solution",
    "offer", "proposal", "plan", "strategy", "tactic",
    "approach", "method", "methodology", "process",
    "procedure", "protocol", "policy", "guideline",
    "rule", "regulation", "standard", "specification",
    "requirement", "criteria", "condition", "constraint",
    "limitation", "restriction", "boundary", "scope",
    "range", "extent", "scale", "magnitude",
    "capacity", "volume", "amount", "quantity", "number",
    "count", "total", "sum", "average", "median",
    "minimum", "maximum", "limit", "threshold",
    "peak", "top", "bottom", "base", "foundation",
    "core", "center", "middle", "edge", "side",
    "front", "back", "end",
    "start", "beginning", "finish", "close",
    "open", "entry", "exit", "door", "gate",
    "window", "portal", "screen", "display", "monitor",
    "panel", "dashboard", "console", "terminal", "shell",
    "interface", "surface", "layer", "level", "tier",
    "grade", "rank",
    "segment", "section", "portion", "piece", "fragment",
    "share", "part",
    "aspect", "facet", "angle", "perspective", "view",
    "standpoint", "viewpoint", "opinion", "thought",
    "idea", "concept", "notion", "belief", "principle",
    "value", "ethic", "moral", "virtue",
    "quality", "excellence", "merit", "worth", "importance",
    "significance", "relevance", "priority", "emphasis",
    "weight", "influence", "impact", "effect", "consequence",
    "result", "outcome", "product", "output", "yield",
    "return", "benefit", "advantage", "gain", "profit",
    "revenue", "income", "earning", "wealth", "asset",
    "capital", "fund", "resource", "reserve", "stock",
    "supply", "inventory", "store", "collection", "cache",
    "order", "sequence", "series", "chain",
    "batch", "lot", "group", "cluster", "bundle",
    "pack", "package", "packet", "bag", "box",
    "container", "holder", "receptacle", "vessel",
    "tank", "tube", "pipe", "conduit", "channel",
    "line", "wire", "cable", "cord", "rope",
    "string", "thread", "strand", "strip", "band",
    "strap", "belt", "link", "ring",
    "loop", "circle", "round", "cycle", "circuit",
    "network", "mesh", "grid", "lattice", "matrix",
    "web", "net", "system", "framework", "structure",
    "architecture", "design", "pattern", "model", "template",
    "blueprint", "schema", "plan", "map", "chart",
    "graph", "diagram", "drawing", "sketch", "outline",
    "frame", "skeleton", "body", "core", "heart",
    "soul", "spirit", "essence", "nature", "character",
    "identity", "personality", "temperament", "disposition",
    "tendency", "inclination", "preference", "liking",
    "choice", "selection", "option", "alternative",
    "decision", "determination", "resolution", "verdict",
    "judgment", "opinion", "view", "belief", "conviction",
    "certainty", "confidence", "trust", "faith", "hope",
    "expectation", "anticipation", "prospect", "outlook",
    "forecast", "projection", "estimate", "prediction",
    "guess", "assumption", "presumption", "supposition",
    "hypothesis", "theory", "thesis", "premise", "claim",
    "argument", "assertion", "statement", "proposition",
    "proposal", "offer", "bid", "tender", "quote",
    "price", "cost", "expense", "fee", "charge",
    "rate", "tariff", "tax", "duty", "levy",
    "fine", "penalty", "sanction", "punishment",
    "reward", "incentive", "bonus", "benefit", "perk",
    "privilege", "right", "entitlement",
    "ownership", "possession", "control", "authority",
    "power", "jurisdiction", "domain", "realm", "field",
    "territory", "area", "region", "district", "zone",
    "sector", "branch",
    "chapter", "article", "section", "clause", "paragraph",
    "item", "entry", "record", "note", "annotation",
    "comment", "remark", "observation", "reflection",
    "thought", "idea", "notion", "concept", "abstraction",
    "generalization", "classification", "categorization",
    "analysis", "synthesis", "evaluation", "assessment",
    "appraisal", "review", "critique", "examination",
    "inspection", "investigation", "exploration", "survey",
    "study", "research", "inquiry", "enquiry", "query",
    "question", "problem", "issue", "concern", "matter",
    "subject", "topic", "theme", "motif", "plot",
    "story", "narrative", "account", "report", "description",
    "explanation", "interpretation", "clarification",
    "elaboration", "amplification", "expansion",
    "extension", "addition", "supplement", "appendix",
    "index", "catalogue", "directory", "register",
    "log", "journal", "diary", "chronicle", "history",
    "timeline", "schedule", "calendar", "agenda", "itinerary",
    "program", "curriculum", "syllabus", "plan", "scheme",
    "arrangement", "organization", "order", "structure",
    "system", "method", "technique", "approach", "strategy",
    "tactic", "maneuver", "move", "step", "action",
    "operation", "procedure", "process", "protocol",
    "workflow", "pipeline", "assembly", "production",
    "construction", "fabrication", "creation", "generation",
    "development", "evolution", "growth", "progress",
    "advancement", "improvement", "betterment", "refinement",
    "enhancement", "upgrade", "update", "revision",
    "modification", "adjustment", "alteration", "change",
    "transformation", "conversion", "transition", "shift",
    "switch", "turn", "bend", "curve", "angle",
    "slope", "grade", "inclination", "tilt", "lean",
    "spin", "rotation", "revolve", "orbit", "cycle",
    "phase", "stage", "step", "degree", "level",
    "rank", "status", "station", "position", "post",
    "place", "spot", "location", "site", "venue",
    "address", "locale", "setting", "environment", "surroundings",
    "context", "milieu", "atmosphere", "climate", "weather",
    "temperature", "pressure", "force", "energy", "power",
    "strength", "intensity", "magnitude", "scale", "proportion",
    "ratio", "rate", "frequency", "velocity", "speed",
    "acceleration", "momentum", "inertia", "mass", "weight",
    "density", "concentration", "volume", "capacity",
    "breadth", "width", "height", "depth", "length",
    "distance", "span", "range", "scope", "reach",
    "spread", "expanse", "extent", "measure", "dimension",
    "size", "magnitude", "bulk", "mass", "volume",
    "quantity", "amount", "sum", "total", "aggregate",
    "piece", "portion", "segment", "fraction", "percentage",
    "ratio", "rate", "proportion", "share", "allotment",
    "allocation", "distribution", "division", "apportionment",
    "assignment", "delegation", "commission", "mandate",
    "charge", "duty", "responsibility", "obligation",
    "liability", "accountability", "answerability",
    "burden", "load", "weight", "pressure", "strain",
    "stress", "tension", "conflict", "struggle", "contest",
    "competition", "rivalry", "opposition", "resistance",
    "defiance", "challenge", "obstacle", "barrier",
    "hurdle", "block", "impediment", "hindrance",
    "setback", "reverse", "difficulty", "trouble",
    "problem", "issue", "dilemma", "predicament",
    "crisis", "emergency", "urgency", "necessity",
    "requirement", "prerequisite", "precondition",
    "qualification", "condition", "stipulation",
    "provision", "clause", "term",
    "demand", "request", "appeal", "petition", "application",
    "proposal", "offer", "bid", "tender", "nomination",
    "selection", "appointment", "designation", "assignment",
    "deployment", "placement", "positioning", "orientation",
    "direction", "guidance", "leadership", "management",
    "administration", "governance", "regulation", "control",
    "supervision", "oversight", "monitoring", "surveillance",
    "observation", "tracking", "tracing", "following",
    "pursuit", "search", "quest", "hunt", "chase",
    "campaign", "drive", "initiative", "project",
    "undertaking", "enterprise", "venture", "endeavor",
    "effort", "attempt", "try", "trial", "experiment",
    "test", "examination", "assessment", "evaluation",
    "appraisal", "review", "audit", "inspection",
    "survey", "poll", "census", "count", "tally",
    "score", "mark", "grade", "rating", "ranking",
    "standing", "status", "position", "class", "rank",
}

_COMMON_ENGLISH_LONG: Set[str] = {
    "calculate", "calculates", "calculated", "calculating", "calculation",
    "calculations",
    "define", "defines", "defined", "defining", "definition", "definitions",
    "determine", "determines", "determined", "determining", "determination",
    "establish", "establishes", "established", "establishing", "establishment",
    "communicate", "communicates", "communicated", "communicating", "communication",
    "organize", "organizes", "organized", "organizing", "organization",
    "demonstrate", "demonstrates", "demonstrated", "demonstrating", "demonstration",
    "distribute", "distributes", "distributed", "distributing", "distribution",
    "contribute", "contributes", "contributed", "contributing", "contribution",
    "investigate", "investigates", "investigated", "investigating", "investigation",
    "evaluate", "evaluates", "evaluated", "evaluating", "evaluation",
    "integrate", "integrates", "integrated", "integrating", "integration",
    "validate", "validates", "validated", "validating", "validation",
    "initialize", "initializes", "initialized", "initializing", "initialization",
    "register", "registers", "registered", "registering", "registration",
    "allocate", "allocates", "allocated", "allocating", "allocation",
    "terminate", "terminates", "terminated", "terminating", "termination",
    "specify", "specifies", "specified", "specifying", "specification",
    "recommend", "recommends", "recommended", "recommending", "recommendation",
    "authorize", "authorizes", "authorized", "authorizing", "authorization",
    "understand", "understands", "understood", "understanding",
    "background", "foreground", "throughout", "throughput",
    "meanwhile", "otherwise", "furthermore", "nevertheless", "nonetheless",
    "according", "following", "including", "regarding",
    "concerning", "considering", "respecting", "surrounding",
    "remaining", "existing", "corresponding", "preceding",
    "information", "application", "situation", "population",
    "association", "environment", "government", "development",
    "achievement", "improvement", "agreement", "statement",
    "treatment", "department", "instrument", "document",
    "management", "arrangement", "requirement", "enforcement",
    "announcement", "performance", "maintenance", "assistance",
    "resistance", "attendance", "importance", "substance",
    "difference", "reference", "preference", "conference",
    "inference", "occurrence", "existence", "persistence",
    "consistence", "instance", "distance", "balance",
    "entrance", "acceptance", "attendance", "insurance",
    "assurance", "endurance", "appearance", "clearance",
    "guidance", "governance", "maintenance",
    "yesterday", "tomorrow", "tonight", "midnight", "afternoon",
    "customer", "partner", "provider", "producer", "supplier",
    "distributor", "manufacturer", "contractor", "consultant",
    "assistant", "attendant", "defendant", "dependant",
    "software", "hardware", "firmware", "middleware",
    "pipeline", "workflow", "database", "network",
    "webpage", "website", "webhook", "firewall", "gateway",
    "console", "desktop", "laptop", "handheld",
    "account", "address", "balance", "budget", "catalog",
    "channel", "chapter", "comment", "content", "context",
    "control", "country", "culture", "current", "custom",
    "damage", "danger", "debate", "decade", "demand",
    "deposit", "despite", "detail", "device", "dinner",
    "direct", "double", "effort", "enable", "energy",
    "engage", "engine", "ensure", "entity", "equity",
    "escape", "estate", "evolve", "exceed", "except",
    "excess", "excuse", "expand", "expect", "expert",
    "export", "expose", "extend", "extent", "fabric",
    "factor", "fairly", "family", "famous", "farmer",
    "fashion", "figure", "filter", "final", "finance",
    "finger", "finish", "flight", "follow", "forest",
    "forget", "formal", "format", "former", "french",
    "friend", "future", "garden", "gender", "gentle",
    "global", "golden", "govern", "growth", "hidden",
    "honest", "impact", "impose", "import", "income",
    "indeed", "indoor", "infant", "inform", "injury",
    "inland", "insect", "insert", "insist", "intact",
    "intake", "intend", "intent", "invent", "invest",
    "invite", "island", "itself", "jacket", "junior",
    "keeper", "kidney", "knight", "labour", "launch",
    "lawyer", "layout", "leader", "league", "lender",
    "length", "lesson", "letter", "likely", "linear",
    "liquid", "listen", "little", "lively", "living",
    "locate", "luxury", "mainly", "manage", "manner",
    "margin", "marine", "marker", "market", "master",
    "matter", "medium", "member", "memory", "mental",
    "merely", "method", "middle", "minute", "mirror",
    "mobile", "model", "modest", "modify", "module",
    "moment", "monkey", "month", "motive", "motor",
    "murder", "muscle", "museum", "mutual", "myself",
    "namely", "narrow", "nation", "native", "nature",
    "nearest", "nearly", "needle", "nobody", "normal",
    "notice", "notion", "number", "object", "obtain",
    "occupy", "offend", "office", "online", "oppose",
    "option", "orange", "orient", "origin", "outlet",
    "output", "palace", "parent", "parish", "parity",
    "partial", "partner", "passage", "passion", "passive",
    "patent", "patrol", "patron", "pattern", "pencil",
    "people", "period", "permit", "person", "phrase",
    "pillar", "planet", "plaster", "player", "pleasure",
    "plenty", "pocket", "poetry", "poison", "police",
    "policy", "polite", "poster", "potato", "potent",
    "powder", "power", "prayer", "present", "preset",
    "pretty", "prevent", "printer", "prison", "privacy",
    "profit", "program", "promise", "prompt", "proper",
    "propose", "protect", "protein", "protest", "provide",
    "public", "pursue", "puzzle", "quality", "quarter",
    "queen", "question", "quiet", "quick", "racial",
    "radical", "railway", "rapidly", "rather", "rating",
    "reader", "readily", "reality", "realize", "reason",
    "recent", "record", "recover", "recycle", "reduce",
    "reform", "refuse", "regard", "regime", "region",
    "regret", "reject", "relate", "relax", "relief",
    "remain", "remark", "remedy", "remind", "remote",
    "remove", "render", "rental", "repair", "repeat",
    "report", "rescue", "resist", "resort", "result",
    "retail", "retain", "retire", "return", "reveal",
    "review", "revolt", "reward", "rhythm", "ritual",
    "rocket", "rotate", "roughly", "routine", "royalty",
    "sacred", "safely", "safety", "salary", "sample",
    "savage", "scheme", "scholar", "screen", "script",
    "search", "season", "second", "secret", "sector",
    "secure", "seldom", "select", "seller", "senior",
    "sensor", "server", "settle", "severe", "shadow",
    "shallow", "shelter", "shield", "signal", "silent",
    "silver", "similar", "simple", "simply", "sister",
    "sketch", "slogan", "slowly", "smooth", "soccer",
    "social", "socket", "sodium", "soften", "solar",
    "solely", "solid", "source", "speaker", "special",
    "species", "sphere", "spider", "spiral", "spirit",
    "sponsor", "square", "stable", "static", "statue",
    "status", "steady", "stellar", "storage", "strain",
    "strange", "stream", "street", "stress", "strict",
    "strike", "string", "stroke", "strong", "studio",
    "submit", "suburb", "sudden", "suffer", "summer",
    "summit", "summon", "supply", "surely", "survey",
    "switch", "symbol", "system", "tablet", "tackle",
    "tactic", "talent", "target", "temple", "tenant",
    "tender", "tennis", "terror", "thesis", "thirty",
    "threat", "thrive", "throat", "throne", "thrust",
    "ticket", "timber", "tissue", "toilet", "tolerate",
    "tongue", "torque", "toward", "towel", "tower",
    "toxin", "traffic", "tragedy", "trailer", "traitor",
    "transfer", "trigger", "trophy", "trouble", "trusted",
    "trustee", "tunnel", "turtle", "twelve", "twenty",
    "typical", "unable", "uncle", "unfair", "unfold",
    "unhappy", "unified", "unique", "united", "unity",
    "unknown", "unlike", "unlock", "unpaid", "unsafe",
    "untrue", "unused", "unveil", "unwise", "update",
    "upgrade", "uphold", "upland", "uplift", "upload",
    "upright", "uproar", "uptake", "upward", "urgent",
    "useful", "useless", "vacant", "vacuum", "vague",
    "valley", "valuable", "vanish", "vapor", "vector",
    "vendor", "venture", "verbal", "verify", "version",
    "versus", "vessel", "viable", "vibrant", "victim",
    "victor", "village", "vintage", "violate", "violent",
    "violet", "virtual", "virtue", "visible", "vision",
    "visual", "vital", "vivid", "volume", "vortex",
    "voyage", "wander", "warmth", "warrant", "warrior",
    "weather", "welcome", "welfare", "western", "whatever",
    "whenever", "whisper", "whistle", "whoever", "wholly",
    "wicked", "widely", "width", "willing", "window",
    "winter", "wisdom", "witness", "wonder", "wooden",
    "worker", "worship", "worthy", "wound", "writer",
    "yearly", "yellow", "young", "youth",
    "arguments", "complete", "analysis", "processing", "advanced",
    "endpoint", "endpoints",
    "happy", "happiness", "unhappy",
    "scientist", "scientists",
    "production", "available", "specific", "essential", "important",
    "significant", "substantial", "sufficient", "effective",
    "efficient", "productive", "reasonable", "practical",
    "reliable", "suitable", "capable", "durable", "flexible",
    "portable", "readable", "scalable", "testable", "deployable",
    "maintainable", "manageable", "compatible", "convertible",
    "implement", "implements", "implemented", "implementing",
    "configure", "configures", "configured", "configuring",
    "identify", "identifies", "identified", "identifying",
    "classify", "classifies", "classified", "classifying",
    "notify", "notifies", "notified", "notifying",
    "verify", "verifies", "verified", "verifying",
    "qualify", "qualifies", "qualified", "qualifying",
    "modify", "modifies", "modified", "modifying",
    "specify", "specifies", "specified", "specifying",
    "justify", "justifies", "justified", "justifying",
}

_COMMON_PROGRAMMING: Set[str] = {
    "False", "None", "True", "and", "as", "assert", "async",
    "await", "break", "class", "continue", "def", "del", "elif",
    "else", "except", "finally", "for", "from", "global", "if",
    "import", "in", "is", "lambda", "nonlocal", "not", "or",
    "pass", "raise", "return", "try", "while", "with", "yield",
    "print", "len", "range", "type", "int", "str", "float",
    "bool", "list", "dict", "set", "tuple", "object", "map",
    "filter", "zip", "enumerate", "sorted", "reversed", "open",
    "input", "format", "repr", "abs", "all", "any", "bin",
    "chr", "dir", "divmod", "eval", "exec", "exit", "hex",
    "id", "isinstance", "issubclass", "iter", "locals", "max",
    "min", "next", "oct", "ord", "pow", "property", "quit",
    "round", "slice", "staticmethod", "sum", "super", "vars",
    "callable", "classmethod", "compile", "complex", "delattr",
    "getattr", "setattr", "hasattr", "hash", "help", "memoryview",
    "__init__", "__str__", "__repr__", "__call__", "__getitem__",
    "__setitem__", "__delitem__", "__len__", "__iter__", "__next__",
    "__enter__", "__exit__", "__name__", "__main__", "__file__",
    "__class__", "__dict__", "__doc__",
    "os", "sys", "json", "re", "math", "time", "datetime",
    "collections", "functools", "itertools", "typing", "pathlib",
    "subprocess", "tempfile", "shutil", "hashlib", "random",
    "string", "textwrap", "inspect", "pprint", "logging",
    "argparse", "configparser", "csv", "io", "base64",
    "dataclasses", "enum", "abc", "copy", "decimal", "fractions",
    "statistics", "uuid", "warnings", "weakref", "numbers",
    "Optional", "List", "Dict", "Set", "Tuple", "Union", "Any",
    "Callable", "Iterable", "Iterator", "Generator", "TypeVar",
    "Generic", "Protocol", "Final", "Literal", "TypedDict",
    "NewType", "cast", "NoReturn", "Never", "Self",
    "TypeAlias", "ClassVar", "NamedTuple",
    "Exception", "BaseException", "ValueError", "TypeError",
    "KeyError", "IndexError", "AttributeError", "ImportError",
    "ModuleNotFoundError", "FileNotFoundError", "ZeroDivisionError",
    "RuntimeError", "OSError", "IOError", "StopIteration",
    "SystemExit", "KeyboardInterrupt", "MemoryError",
    "OverflowError", "RecursionError", "NotImplementedError",
    "LookupError", "ArithmeticError", "EnvironmentError",
    "self", "cls", "args", "kwargs", "items", "keys", "values",
    "other", "result", "output", "input", "data", "text",
    "content", "status", "error", "message", "value", "key",
    "index", "count", "total", "item", "element", "node",
    "name", "path", "file", "line", "flag", "mode",
    "size", "pos", "prev", "next", "curr", "head", "tail",
    "left", "right", "top", "bottom", "start", "end",
    "min", "max", "sum", "avg", "len", "tmp", "temp",
    "src", "dst", "source", "target", "config", "conf",
    "param", "params", "opt", "opts", "arg", "args",
    "new", "old", "first", "last", "mid", "high", "low",
    "ptr", "ref", "init", "done", "ok", "err",
    "iter", "idx", "acc", "rem", "mod", "mul", "div",
    "sub", "add", "cmp", "del", "inc", "dec", "neg",
    "pos", "abs", "sig", "num", "den", "exp", "log",
    "sin", "cos", "tan", "deg", "rad", "res", "buf",
    "buffer", "offset", "stride", "length", "scale",
    "shift", "mask", "byte", "word", "addr", "reg",
    "stack", "heap", "queue", "pool", "slot", "page",
    "block", "packet", "frame", "segment", "sector",
    "cache", "flush", "sync", "async", "lock", "mutex",
    "cond", "signal", "event", "timer", "clock", "tick",
    "rate", "freq", "period", "delay", "warn", "fatal",
    "debug", "info", "trace", "notice", "alert", "crit",
    "emerg", "panic", "fault", "retry", "abort",
    "skip", "next", "prev", "first", "last", "begin",
    "over", "under", "inner", "outer", "upper", "lower",
    "eq", "ne", "lt", "gt", "le", "ge", "add", "sub",
    "mul", "div", "mod", "pow", "neg", "pos", "abs",
    "inv", "and", "or", "xor", "not", "lshift", "rshift",
    "iadd", "isub", "imul", "idiv", "ipow", "imod",
    "plus", "minus", "times", "divide",
    "undefined", "null", "NaN", "console", "log", "error",
    "warn", "debug", "info", "require", "module", "exports",
    "export", "import", "default", "from", "as", "const",
    "let", "var", "function", "return", "if", "else",
    "for", "while", "do", "switch", "case", "break",
    "continue", "new", "delete", "typeof", "instanceof",
    "this", "super", "class", "extends", "yield", "async",
    "await", "try", "catch", "finally", "throw", "of",
    "in", "with", "void", "declare", "keyof", "readonly",
    "static", "public", "private", "protected", "abstract",
    "implements", "interface", "type", "namespace", "module",
    "any", "unknown", "never", "void", "string", "number",
    "boolean", "symbol", "bigint", "object", "array",
    "tuple", "enum", "union", "intersection", "optional",
    "required", "partial", "readonly", "record", "pick",
    "omit", "extract", "exclude", "nonnullable",
    "Parameters", "ConstructorParameters", "ReturnType",
    "InstanceType", "ThisType", "OmitThisParameter",
    "ThisParameterType",
    "SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE",
    "CREATE", "ALTER", "DROP", "TABLE", "INDEX", "VIEW",
    "INTO", "VALUES", "SET", "AND", "OR", "NOT", "IN",
    "LIKE", "BETWEEN", "IS", "NULL", "AS", "ON", "JOIN",
    "LEFT", "RIGHT", "INNER", "OUTER", "CROSS", "FULL",
    "GROUP", "BY", "ORDER", "ASC", "DESC", "HAVING",
    "LIMIT", "OFFSET", "UNION", "ALL", "DISTINCT", "EXISTS",
    "CASE", "WHEN", "THEN", "ELSE", "END", "CAST",
    "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT",
    "GRANT", "REVOKE", "TRIGGER", "PROCEDURE", "FUNCTION",
    "PRIMARY", "KEY", "FOREIGN", "REFERENCES", "CONSTRAINT",
    "UNIQUE", "CHECK", "DEFAULT", "AUTO_INCREMENT",
    "INTEGER", "INT", "VARCHAR", "TEXT", "BOOLEAN", "BOOL",
    "FLOAT", "DOUBLE", "DECIMAL", "DATE", "TIMESTAMP",
    "BLOB", "CLOB", "BINARY", "VARBINARY",
    "div", "span", "class", "id", "style", "href", "src",
    "alt", "title", "rel", "type", "name", "value",
    "action", "method", "disabled", "readonly", "checked",
    "selected", "hidden", "required", "autofocus",
    "placeholder", "pattern", "min", "max", "step",
    "width", "height", "margin", "padding", "border",
    "display", "position", "float", "clear", "overflow",
    "visible", "hidden", "scroll", "auto", "block",
    "inline", "inline-block", "flex", "grid", "table",
    "absolute", "relative", "fixed", "static", "sticky",
    "center", "top", "bottom", "left", "right",
    "background", "color", "font", "size", "weight",
    "align", "justify", "text", "decoration", "transform",
    "transition", "animation", "shadow", "opacity",
    "container", "wrapper", "header", "footer", "main",
    "nav", "section", "article", "aside", "button",
    "input", "select", "option", "label", "form",
    "table", "tr", "td", "th", "thead", "tbody", "tfoot",
    "ul", "ol", "li", "dl", "dt", "dd", "img", "video",
    "audio", "canvas", "svg", "iframe", "script",
    "link", "meta", "base", "body", "head", "html",
    "doctype", "charset", "viewport", "description",
    "keywords", "author", "robots", "canonical",
    "git", "npm", "yarn", "pip", "docker", "kubernetes",
    "nginx", "apache", "redis", "postgres", "mysql",
    "mongodb", "sqlite", "elasticsearch", "kafka",
    "rabbitmq", "prometheus", "grafana", "jenkins",
    "github", "gitlab", "bitbucket", "jira", "confluence",
    "slack", "discord", "telegram", "webpack", "vite",
    "esbuild", "rollup", "parcel", "gulp", "grunt",
    "babel", "typescript", "javascript", "python",
    "java", "golang", "rust", "cplusplus", "ruby",
    "php", "swift", "kotlin", "scala", "haskell",
    "elixir", "clojure", "erlang", "dart", "lua",
    "perl", "rlang", "matlab", "julia", "fortran",
    "cobol", "pascal", "prolog", "lisp", "scheme",
    "react", "vue", "angular", "svelte", "solid",
    "nextjs", "nuxt", "gatsby", "remix", "astro",
    "django", "flask", "fastapi", "spring", "laravel",
    "rails", "express", "nestjs", "gin", "echo",
    "fiber", "actix", "rocket", "axum", "tower",
    "tokio", "asyncstd", "smol", "rayon", "crossbeam",
    "pytorch", "tensorflow", "jax", "keras", "scikit",
    "numpy", "pandas", "scipy", "matplotlib", "seaborn",
    "plotly", "bokeh", "altair", "streamlit", "gradio",
    "dash", "shiny", "tableau", "powerbi",
    "bootstrap", "tailwind", "chakra", "mui", "antd",
    "shadcn", "radix", "headless", "primereact",
    "jest", "vitest", "mocha", "chai", "sinon",
    "cypress", "playwright", "puppeteer", "selenium",
    "pytest", "unittest", "nose", "doctest",
    "eslint", "prettier", "black", "ruff", "mypy",
    "flake8", "pylint", "isort", "clangformat",
    "golangci", "rustfmt", "clippy",
    "dotall", "multiline", "ignorecase", "verbose",
    "unicode", "ascii", "locale", "debug",
}

_SAFE_LEXICON: Set[str] = {
    *(w.lower() for w in _SAFE_ACRONYMS),
    *(w.lower() for w in _NEVER_NORMALISE),
    *(w.lower() for w in _COMMON_ENGLISH),
    *(w.lower() for w in _COMMON_ENGLISH_LONG),
    *(w.lower() for w in _COMMON_PROGRAMMING),
}


class LexiconNormalizer:
    """Deterministic token analyzer for user-specific vocabulary detection.

    Provides methods to identify UUIDs, hashes, long tokens, code
    identifiers, email addresses, and rare/unusual words in text.

    ``sanitize_text()`` is a pass-through — no placeholder substitution
    or text modification is performed by this class.  Use it as a
    library import for analysis; pair with a dedicated redaction plugin
    for actual replacement.

    Analysis results are available via ``analyze_text()`` which returns
    a structured report of all detected token categories.
    """

    MAX_TOKEN_LENGTH: int = 40
    MIN_RARE_WORD_LENGTH: int = 8

    _UUID_REGEX: re.Pattern = re.compile(
        r"\b[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}\b",
        re.IGNORECASE,
    )
    _HASH_REGEX: re.Pattern = re.compile(
        r"\b[0-9a-f]{32,}\b",
        re.IGNORECASE,
    )
    _LONG_TOKEN_REGEX: re.Pattern = re.compile(
        r"\b[a-zA-Z0-9_-]{40,}\b",
    )
    _IDENTIFIER_REGEX: re.Pattern = re.compile(
        r"\b[a-zA-Z_][a-zA-Z0-9]*(?:_[a-zA-Z0-9]+)*\b"
    )
    _EMAIL_REGEX: re.Pattern = re.compile(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    )

    def __init__(
        self,
        max_token_length: int = 40,
        min_rare_word: int = 8,
    ) -> None:
        self._max_token = max_token_length
        self._min_rare = min_rare_word

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sanitize_text(self, text: str) -> str:
        """Pass-through — no replacement performed.

        This plugin does not modify text.  Use the dedicated
        redaction plugin for placeholder substitution.
        """
        return text

    def restore_text(self, text: str) -> str:
        """Pass-through — no restoration performed."""
        return text

    def reset(self) -> None:
        """No-op."""
        pass

    @property
    def token_count(self) -> int:
        return 0

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    @staticmethod
    def _strip_protected_regions(text: str) -> str:
        """Remove code blocks, inline code, and bracket-enclosed content
        from *text* so downstream analysis does not flag tokens in those
        regions.

        Protected regions:
          - Fenced code blocks (triple backticks, with optional lang)
          - Inline code (single backticks)
          - Square-bracket-enclosed sections ``[...]`` (common in prompts
            for tool calls, markdown link text, metadata)
          - Parenthesised sections ``(...)`` (URLs, funcalls, markdown
            link targets)
          - Curly-brace sections ``{...}`` (JSON, dicts, template vars)
        """
        result = text

        # Fenced code blocks: ```...``` (non-greedy, multiline)
        result = re.sub(
            r"```.*?```",
            " ",
            result,
            count=0,
            flags=re.DOTALL,
        )

        # Inline code: `...`
        result = re.sub(r"`[^`]+`", " ", result)

        # Remove markdown links entirely: [text](url) or [text]
        result = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", result)

        # Square brackets: [...] (but not _VEN_ placeholders)
        result = re.sub(r"\[[^\]]*\]", " ", result)

        # Parentheses: (...)  — single level, no nesting
        result = re.sub(r"\([^)]*\)", " ", result)

        # Curly braces: {...} — single level, no nesting
        result = re.sub(r"\{[^}]*\}", " ", result)

        return result

    def analyze_text(self, text: str) -> Dict[str, List[str]]:
        """Analyze *text* and return a report of detected token categories.

        Returns a dict with keys:
          - ``"emails"`` — email addresses found
          - ``"uuids"`` — UUID/GUID tokens
          - ``"hashes"`` — hash-like hex strings (32+ chars)
          - ``"long_tokens"`` — tokens >= 40 chars
          - ``"identifiers"`` — camelCase, PascalCase, snake_case tokens
          - ``"rare_words"`` — words >= 8 chars not in the safe lexicon

        Code blocks, inline code, and bracket-enclosed content are
        excluded from analysis to avoid false positives on code,
        metadata, and markdown syntax.
        """
        report: Dict[str, List[str]] = {
            "emails": [],
            "uuids": [],
            "hashes": [],
            "long_tokens": [],
            "identifiers": [],
            "rare_words": [],
        }

        if not text:
            return report

        # Strip protected regions for analysis (original text unchanged)
        stripped = self._strip_protected_regions(text)

        report["emails"] = [
            m.group(0) for m in self._EMAIL_REGEX.finditer(stripped)
        ]
        report["uuids"] = [
            m.group(0) for m in self._UUID_REGEX.finditer(stripped)
        ]
        report["hashes"] = [
            m.group(0) for m in self._HASH_REGEX.finditer(stripped)
        ]
        report["long_tokens"] = [
            m.group(0) for m in self._LONG_TOKEN_REGEX.finditer(stripped)
        ]

        # Code identifiers
        identifiers = set()
        for m in self._IDENTIFIER_REGEX.finditer(stripped):
            token = m.group(0)
            if self._is_code_identifier(token):
                identifiers.add(token)
        report["identifiers"] = sorted(identifiers)

        # Rare words
        rare = set()
        for m in re.finditer(
            r"(?<![a-zA-Z0-9_\-])([a-zA-Z_][a-zA-Z0-9_]*)(?![a-zA-Z0-9_\-])",
            stripped,
        ):
            token = m.group(0)
            if self._is_rare_word(token):
                rare.add(token)
        report["rare_words"] = sorted(rare)

        return report

    def is_safe_word(self, token: str) -> bool:
        """Check if *token* is a known safe word (direct or derived)."""
        if not token:
            return False
        return self._is_safe_derived(token)

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    def _is_code_identifier(self, token: str) -> bool:
        """Check if *token* looks like a code identifier (not plain English)."""
        if len(token) <= 2:
            return False
        if token.isdigit():
            return False
        if token.lower() in _SAFE_LEXICON or token in _SAFE_ACRONYMS:
            return False
        if token.startswith("_VEN_") or token.startswith("__"):
            return False
        if token.isupper() and len(token) <= 8:
            return False
        if token.islower():
            return False

        has_upper = bool(re.search(r"[A-Z]", token))
        has_underscore = "_" in token
        if not (has_upper or has_underscore):
            return False

        # camelCase
        if re.match(r"^[a-z]+[A-Z]", token):
            return True
        # PascalCase
        if re.match(r"^[A-Z][a-z]+[A-Z]", token):
            return True
        # snake_case (not all safe parts)
        if "_" in token and token.islower():
            parts = token.split("_")
            return not all(p in _SAFE_LEXICON for p in parts)

        return False

    def _is_rare_word(self, token: str) -> bool:
        """Check if *token* is a rare/unusual word (not safe, not derived)."""
        if not token:
            return False
        if len(token) < self._min_rare:
            return False
        if self._is_safe_derived(token):
            return False
        if re.search(r"\d", token):
            digit_ratio = sum(1 for c in token if c.isdigit()) / len(token)
            if digit_ratio > 0.4:
                return False
        if token.startswith("_VEN_") or (
            token.startswith("[") and token.endswith("]")
        ):
            return False
        if "/" in token or "\\" in token or "://" in token:
            return False
        if re.match(r"^[0-9a-f]{8,}$", token, re.IGNORECASE):
            return False
        return True

    def _is_safe_derived(self, token: str) -> bool:
        """Check if *token* is in the safe lexicon or a common derivation."""
        lower = token.lower()

        if lower in _SAFE_LEXICON or token in _SAFE_ACRONYMS:
            return True
        if lower in _NEVER_NORMALISE:
            return True

        # Inflected forms
        if lower.endswith("s") and lower[:-1] in _SAFE_LEXICON:
            return True
        if lower.endswith("es") and lower[:-2] in _SAFE_LEXICON:
            return True
        if lower.endswith("ed") and lower[:-2] in _SAFE_LEXICON:
            return True
        if lower.endswith("ing") and lower[:-3] in _SAFE_LEXICON:
            return True
        if lower.endswith("ing") and lower[:-3] + "e" in _SAFE_LEXICON:
            return True
        if lower.endswith("ly") and lower[:-2] in _SAFE_LEXICON:
            return True

        # -tion forms
        if lower.endswith("tion"):
            if lower[:-4] + "e" in _SAFE_LEXICON:
                return True
            if lower[:-4] in _SAFE_LEXICON:
                return True
            if lower[:-3] + "e" in _SAFE_LEXICON:
                return True
            if lower.endswith("ition") and lower[:-5] + "e" in _SAFE_LEXICON:
                return True
            if lower.endswith("ation") and lower[:-5] in _SAFE_LEXICON:
                return True
            if lower.endswith("ation") and lower[:-5] + "e" in _SAFE_LEXICON:
                return True
            if lower.endswith("ization") and lower[:-6] + "e" in _SAFE_LEXICON:
                return True
            if lower.endswith("ification") and lower[:-7] + "y" in _SAFE_LEXICON:
                return True

        # -sion forms
        if lower.endswith("sion"):
            if lower[:-4] + "d" in _SAFE_LEXICON:
                return True
            if lower[:-4] + "e" in _SAFE_LEXICON:
                return True

        # -ment forms
        if lower.endswith("ment"):
            if lower[:-4] in _SAFE_LEXICON:
                return True
            if lower[:-4] + "e" in _SAFE_LEXICON:
                return True

        # -able/-ible
        if lower.endswith("able"):
            if lower[:-4] in _SAFE_LEXICON:
                return True
            if lower[:-4] + "e" in _SAFE_LEXICON:
                return True
            if lower[:-4] + "y" in _SAFE_LEXICON:
                return True
        if lower.endswith("ible"):
            if lower[:-4] in _SAFE_LEXICON:
                return True
            if lower[:-4] + "e" in _SAFE_LEXICON:
                return True

        # -ity forms
        if lower.endswith("ity"):
            if lower[:-3] in _SAFE_LEXICON:
                return True
            if lower[:-3] + "e" in _SAFE_LEXICON:
                return True
            if lower[:-3] + "y" in _SAFE_LEXICON:
                return True
            if lower[:-5] + "le" in _SAFE_LEXICON:
                return True

        # -ive forms
        if lower.endswith("ive"):
            if lower[:-3] in _SAFE_LEXICON:
                return True
            if lower[:-3] + "e" in _SAFE_LEXICON:
                return True
            if lower[:-3] + "ion" in _SAFE_LEXICON:
                return True

        # -ness forms
        if lower.endswith("ness"):
            if lower[:-4] in _SAFE_LEXICON:
                return True
            if lower[:-4] + "y" in _SAFE_LEXICON:
                return True
            if lower[:-4] + "le" in _SAFE_LEXICON:
                return True
            if len(lower) > 6 and lower[:-4].endswith("i"):
                if lower[:-5] + "y" in _SAFE_LEXICON:
                    return True

        # -al forms
        if lower.endswith("al"):
            if lower[:-2] in _SAFE_LEXICON:
                return True
            if lower[:-2] + "e" in _SAFE_LEXICON:
                return True
            if lower[:-2] + "y" in _SAFE_LEXICON:
                return True

        # -ic forms
        if lower.endswith("ic"):
            if lower[:-2] in _SAFE_LEXICON:
                return True
            if lower[:-2] + "y" in _SAFE_LEXICON:
                return True

        # -ous forms
        if lower.endswith("ous"):
            if lower[:-3] in _SAFE_LEXICON:
                return True
            if lower[:-3] + "e" in _SAFE_LEXICON:
                return True
            if lower[:-3] + "y" in _SAFE_LEXICON:
                return True

        # -ful, -less, -ward
        if lower.endswith("ful") and lower[:-3] in _SAFE_LEXICON:
            return True
        if lower.endswith("less") and lower[:-4] in _SAFE_LEXICON:
            return True
        if lower.endswith("ward") and lower[:-4] in _SAFE_LEXICON:
            return True

        # -ist, -ism, -ize, -ise
        if lower.endswith("ist"):
            if lower[:-3] in _SAFE_LEXICON:
                return True
            if lower[:-3] + "e" in _SAFE_LEXICON:
                return True
            if lower[:-3] + "y" in _SAFE_LEXICON:
                return True
        if lower.endswith("ism"):
            if lower[:-3] in _SAFE_LEXICON:
                return True
            if lower[:-3] + "e" in _SAFE_LEXICON:
                return True
            if lower[:-3] + "y" in _SAFE_LEXICON:
                return True
        if lower.endswith("ize"):
            if lower[:-3] in _SAFE_LEXICON:
                return True
            if lower[:-3] + "e" in _SAFE_LEXICON:
                return True
        if lower.endswith("ise"):
            if lower[:-3] in _SAFE_LEXICON:
                return True
            if lower[:-3] + "e" in _SAFE_LEXICON:
                return True

        # Comparative/superlative
        if lower.endswith("er") and lower[:-2] in _SAFE_LEXICON:
            return True
        if lower.endswith("est") and lower[:-3] in _SAFE_LEXICON:
            return True

        # -th forms
        if lower.endswith("th") and len(lower) >= 5:
            if lower[:-2] in _SAFE_LEXICON:
                return True
            if lower[:-2] + "ng" in _SAFE_LEXICON:
                return True
            if lower[:-2] + "n" in _SAFE_LEXICON:
                return True

        # -ance/-ence
        if lower.endswith("ance"):
            if lower[:-4] in _SAFE_LEXICON:
                return True
            if lower[:-4] + "e" in _SAFE_LEXICON:
                return True
            if lower[:-4] + "y" in _SAFE_LEXICON:
                return True
            if lower.endswith("ance") and lower[:-3] + "t" in _SAFE_LEXICON:
                return True
        if lower.endswith("ence"):
            if lower[:-4] in _SAFE_LEXICON:
                return True
            if lower[:-4] + "e" in _SAFE_LEXICON:
                return True
            if lower[:-4] + "y" in _SAFE_LEXICON:
                return True
            if lower.endswith("ence") and lower[:-3] + "t" in _SAFE_LEXICON:
                return True

        return False
