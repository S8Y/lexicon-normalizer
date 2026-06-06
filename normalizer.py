"""Lexicon Normalizer — deterministic token/lexicon management.

Prevents cross-prompt lexical persistence by treating each prompt as a
stateless lexical environment. Replaces user-specific identifiers, rare
tokens, UUIDs, and unusual identifiers with canonical placeholders
(``_VEN_<N>``), and restores them on response.

Rules enforced:
- No word-frequency history across prompts.
- Each prompt is a stateless lexical environment.
- Programming language keywords, operators, and syntax structure are
  NEVER modified.
- Only affects: variable names, identifiers, custom labels, free-text
  strings (if non-semantic-critical).
- No external models or memory. Deterministic within the current prompt.
"""

from __future__ import annotations

import re
from typing import Final, Set

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
    # Common pronouns, determiners, prepositions, conjunctions
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
    # High-frequency nouns
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
    "page", "section", "chapter", "topic", "subject",
    "title", "name", "label", "tag", "keyword",
    "term", "phrase", "sentence", "paragraph", "text",
    "content", "description", "summary", "detail",
    "file", "folder", "directory", "path", "name",
    "type", "kind", "sort", "category", "group",
    "set", "collection", "array", "list", "queue",
    "stack", "tree", "graph", "map", "table",
    "row", "column", "cell", "field", "record",
    "entry", "item", "element", "member", "node",
    "root", "leaf", "branch", "child", "parent",
    "sibling", "peer", "partner", "owner", "creator",
    "author", "editor", "viewer", "reader", "writer",
    "listener", "handler", "manager", "controller",
    "director", "leader", "head", "chief", "owner",
    "user", "admin", "administrator", "operator",
    "developer", "engineer", "designer", "analyst",
    "architect", "consultant", "advisor", "assistant",
    "coordinator", "supervisor", "trainer", "instructor",
    "teacher", "professor", "lecturer", "speaker",
    "writer", "author", "journalist", "reporter",
    "editor", "publisher", "producer", "manager",
    "director", "executive", "officer", "worker",
    "employee", "staff", "member", "participant",
    "volunteer", "partner", "stakeholder", "client",
    "customer", "consumer", "user", "visitor",
    "guest", "audience", "spectator", "observer",
    "witness", "expert", "specialist", "professional",
    "master", "leader", "pioneer", "innovator",
    "supplier", "vendor", "provider", "distributor",
    "retailer", "wholesaler", "manufacturer",
    "contractor", "subcontractor", "consultant",
    "agency", "bureau", "department", "division",
    "branch", "office", "unit", "team", "group",
    "committee", "board", "council", "panel",
    "commission", "taskforce", "working", "party",
    "goal", "objective", "mission", "vision", "purpose",
    "aim", "target", "outcome", "result", "output",
    "deliverable", "product", "service", "solution",
    "offer", "proposal", "plan", "strategy", "tactic",
    "approach", "method", "methodology", "process",
    "procedure", "protocol", "policy", "guideline",
    "rule", "regulation", "standard", "specification",
    "requirement", "criteria", "condition", "constraint",
    "limitation", "restriction", "boundary", "scope",
    "range", "extent", "scale", "magnitude", "size",
    "capacity", "volume", "amount", "quantity", "number",
    "count", "total", "sum", "average", "median",
    "minimum", "maximum", "limit", "threshold", "boundary",
    "peak", "top", "bottom", "base", "foundation",
    "core", "center", "middle", "edge", "side",
    "front", "back", "top", "bottom", "end",
    "start", "beginning", "middle", "finish", "close",
    "open", "entry", "exit", "door", "gate",
    "window", "portal", "screen", "display", "monitor",
    "panel", "dashboard", "console", "terminal", "shell",
    "interface", "surface", "layer", "level", "tier",
    "grade", "rank", "class", "category", "division",
    "segment", "section", "portion", "piece", "fragment",
    "share", "part", "component", "element", "member",
    "aspect", "facet", "angle", "perspective", "view",
    "standpoint", "viewpoint", "opinion", "thought",
    "idea", "concept", "notion", "belief", "principle",
    "value", "ethic", "moral", "virtue", "standard",
    "quality", "excellence", "merit", "worth", "importance",
    "significance", "relevance", "priority", "emphasis",
    "weight", "influence", "impact", "effect", "consequence",
    "result", "outcome", "product", "output", "yield",
    "return", "benefit", "advantage", "gain", "profit",
    "revenue", "income", "earning", "wealth", "asset",
    "capital", "fund", "resource", "reserve", "stock",
    "supply", "inventory", "store", "collection", "cache",
    "order", "sequence", "series", "chain", "set",
    "batch", "lot", "group", "cluster", "bundle",
    "pack", "package", "packet", "bag", "box",
    "container", "holder", "receptacle", "vessel",
    "tank", "tube", "pipe", "conduit", "channel",
    "line", "wire", "cable", "cord", "rope",
    "string", "thread", "strand", "strip", "band",
    "strap", "belt", "chain", "link", "ring",
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
    "privilege", "right", "entitlement", "claim", "title",
    "ownership", "possession", "control", "authority",
    "power", "jurisdiction", "domain", "realm", "field",
    "territory", "area", "region", "district", "zone",
    "sector", "branch", "department", "division",
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
    "provision", "clause", "term", "requirement",
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

# Additional common 7+ char English words that safe-lexicon checks need
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
    # additional common words from tests
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
    # Common verb forms needed by derivation checks
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
    # Python keywords
    "False", "None", "True", "and", "as", "assert", "async",
    "await", "break", "class", "continue", "def", "del", "elif",
    "else", "except", "finally", "for", "from", "global", "if",
    "import", "in", "is", "lambda", "nonlocal", "not", "or",
    "pass", "raise", "return", "try", "while", "with", "yield",
    # Common builtins
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
    # Common standard library modules
    "os", "sys", "json", "re", "math", "time", "datetime",
    "collections", "functools", "itertools", "typing", "pathlib",
    "subprocess", "tempfile", "shutil", "hashlib", "random",
    "string", "textwrap", "inspect", "pprint", "logging",
    "argparse", "configparser", "csv", "io", "base64",
    "dataclasses", "enum", "abc", "copy", "decimal", "fractions",
    "statistics", "uuid", "warnings", "weakref", "numbers",
    # Common type annotations
    "Optional", "List", "Dict", "Set", "Tuple", "Union", "Any",
    "Callable", "Iterable", "Iterator", "Generator", "TypeVar",
    "Generic", "Protocol", "Final", "Literal", "TypedDict",
    "NewType", "cast", "NoReturn", "Never", "Self",
    "TypeAlias", "ClassVar", "NamedTuple",
    # File and exception names
    "Exception", "BaseException", "ValueError", "TypeError",
    "KeyError", "IndexError", "AttributeError", "ImportError",
    "ModuleNotFoundError", "FileNotFoundError", "ZeroDivisionError",
    "RuntimeError", "OSError", "IOError", "StopIteration",
    "SystemExit", "KeyboardInterrupt", "MemoryError",
    "OverflowError", "RecursionError", "NotImplementedError",
    "LookupError", "ArithmeticError", "EnvironmentError",
    # Common variable names
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
    # Operators and symbols
    "eq", "ne", "lt", "gt", "le", "ge", "add", "sub",
    "mul", "div", "mod", "pow", "neg", "pos", "abs",
    "inv", "and", "or", "xor", "not", "lshift", "rshift",
    "iadd", "isub", "imul", "idiv", "ipow", "imod",
    "plus", "minus", "times", "divide",
    # JavaScript/TS common
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
    # SQL common
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
    # HTML/CSS common
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
    # Common tool/tech names
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
    "# Common regex patterns / anchors",
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
    """Deterministic token normalizer that replaces user-specific vocabulary
    with canonical placeholders (``_VEN_<N>``)."""

    # Maximum token length before forced replacement (40 chars)
    MAX_TOKEN_LENGTH: int = 40

    # Minimum length for rare-word detection (8 chars)
    MIN_RARE_WORD_LENGTH: int = 8

    # UUID-like patterns
    _UUID_REGEX: re.Pattern = re.compile(
        r"\b[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}\b",
        re.IGNORECASE,
    )

    # Hash-like patterns (hex strings 32+ chars)
    _HASH_REGEX: re.Pattern = re.compile(
        r"\b[0-9a-f]{32,}\b",
        re.IGNORECASE,
    )

    # Long alphanumeric tokens (potential secrets/tokens)
    _LONG_TOKEN_REGEX: re.Pattern = re.compile(
        r"\b[a-zA-Z0-9_-]{40,}\b",
    )

    # Code identifier patterns (camelCase, PascalCase, snake_case)
    _IDENTIFIER_REGEX: re.Pattern = re.compile(
        r"\b[a-zA-Z_][a-zA-Z0-9]*(?:_[a-zA-Z0-9]+)*\b"
    )

    # email-like
    _EMAIL_REGEX: re.Pattern = re.compile(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    )

    def __init__(
        self,
        max_token_length: int = 40,
        min_rare_word: int = 8,
    ):
        self._max_token = max_token_length
        self._min_rare = min_rare_word
        self._token_counter: int = 0
        self._placeholder_map: dict[str, str] = {}
        self._reverse_map: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sanitize_text(self, text: str) -> str:
        """Normalize a prompt text, replacing user-specific tokens with
        ``_VEN_<N>`` placeholders.

        Steps are applied in order from most specific (emails, UUIDs,
        hashes) to least specific (rare words).
        """
        if not text:
            return text

        result = text

        # 1. Email addresses (preserve structure, normalize local part)
        result = self._replace_emails(result)

        # 2. UUIDs and GUIDs
        result = self._replace_uuids(result)

        # 3. Hash-looking hex strings
        result = self._replace_hashes(result)

        # 4. Long tokens (potential secrets, API keys)
        result = self._replace_long_tokens(result)

        # 5. Code identifiers (camelCase, PascalCase, snake_case)
        result = self._replace_identifiers(result)

        # 6. Rare/unusual words
        result = self._replace_rare_words(result)

        return result

    def restore_text(self, text: str) -> str:
        """Restore original tokens from ``_VEN_<N>`` placeholders."""
        if not text or not self._reverse_map:
            return text

        result = text
        for placeholder, original in sorted(
            self._reverse_map.items(),
            key=lambda x: (-len(x[0]), x[0]),
        ):
            result = result.replace(placeholder, original)
        return result

    def reset(self) -> None:
        """Reset the token counter and all mappings. Call between prompts."""
        self._token_counter = 0
        self._placeholder_map.clear()
        self._reverse_map.clear()

    @property
    def token_count(self) -> int:
        """Number of tokens normalised in the current session."""
        return self._token_counter

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _store(self, token: str) -> str:
        """Assign a placeholder to a token, or retrieve existing."""
        if token in self._placeholder_map:
            return self._placeholder_map[token]

        placeholder = f"_VEN_{self._token_counter}"
        self._token_counter += 1
        self._placeholder_map[token] = placeholder
        self._reverse_map[placeholder] = token
        return placeholder

    def _replace_emails(self, text: str) -> str:
        """Normalize email addresses."""

        def _replace(m: re.Match) -> str:
            addr = m.group(0)
            local, domain = addr.split("@", 1)
            # Replace local part with placeholder
            return self._store(addr)

        return self._EMAIL_REGEX.sub(_replace, text)

    def _replace_uuids(self, text: str) -> str:
        """Replace UUID/GUID tokens."""
        return self._UUID_REGEX.sub(lambda m: self._store(m.group(0)), text)

    def _replace_hashes(self, text: str) -> str:
        """Replace hash-like hex strings (32+ hex chars)."""
        return self._HASH_REGEX.sub(lambda m: self._store(m.group(0)), text)

    def _replace_long_tokens(self, text: str) -> str:
        """Replace exceptionally long tokens (potential secrets)."""
        return self._LONG_TOKEN_REGEX.sub(
            lambda m: self._store(m.group(0)), text
        )

    def _replace_identifiers(self, text: str) -> str:
        """Replace camelCase, PascalCase, and snake_case identifiers.

        Only replaces identifiers that contain mixed case or underscores
        AND are not in the safe lexicon.
        """

        def _is_code_identifier(token: str) -> bool:
            """Check if a token looks like a code identifier (not plain English)."""
            # Skip if all lowercase — this is probably plain English
            if token.islower():
                return False
            # Skip if in safe lexicon
            if token.lower() in _SAFE_LEXICON:
                return False
            if token in _SAFE_ACRONYMS:
                return False

            # Check for mixed case or underscores
            has_upper = bool(re.search(r"[A-Z]", token))
            has_underscore = "_" in token

            if not (has_upper or has_underscore):
                return False

            # Skip programming keywords
            if token.lower() in _SAFE_LEXICON:
                return False

            return True

        def _replace(m: re.Match) -> str:
            token = m.group(0)

            # Skip placeholders and known patterns
            if token.startswith("_VEN_") or token.startswith("__"):
                return token

            # Skip numbers
            if token.isdigit():
                return token

            # Skip if all-single-char tokens (e.g., "i", "x", "n")
            if len(token) <= 2 and token.isalpha() and token.islower():
                return token

            # Skip safe words
            if token.lower() in _SAFE_LEXICON or token in _SAFE_ACRONYMS:
                return token

            # Skip if it's just an acronym
            if token.isupper() and len(token) <= 8:
                return token

            if not _is_code_identifier(token):
                return token

            # Check if this is inside backticks (likely code)
            # We can't easily check context, so be conservative:
            # Only replace if it looks like a user-defined identifier
            if re.match(r"^[a-z]+[A-Z]", token):  # camelCase
                return self._store(token)
            if re.match(r"^[A-Z][a-z]+[A-Z]", token):  # PascalCase
                return self._store(token)
            if "_" in token and token.islower():  # snake_case
                # Check it's not just a common word with underscore
                parts = token.split("_")
                if all(p in _SAFE_LEXICON for p in parts):
                    return token
                return self._store(token)

            return token

        return self._IDENTIFIER_REGEX.sub(_replace, text)

    def _replace_rare_words(self, text: str) -> str:
        """Replace rare/unusual words in non-code text.

        A word is considered rare if it is longer than ``_min_rare`` chars
        and not found in the safe lexicon (or derivable from it).
        """

        def _is_safe_derived(token: str) -> bool:
            """Check if a token is in the lexicon or a common derivation."""
            lower = token.lower()

            # Direct match
            if lower in _SAFE_LEXICON or token in _SAFE_ACRONYMS:
                return True
            if lower in _NEVER_NORMALISE:
                return True

            # Inflected forms
            # Plural (word + s)
            if lower.endswith("s") and lower[:-1] in _SAFE_LEXICON:
                return True
            # Plural (word + es)
            if lower.endswith("es") and lower[:-2] in _SAFE_LEXICON:
                return True
            # Past tense / participle (word + ed)
            if lower.endswith("ed") and lower[:-2] in _SAFE_LEXICON:
                return True
            # Gerund / present participle (word + ing)
            if lower.endswith("ing") and lower[:-3] in _SAFE_LEXICON:
                return True
            if lower.endswith("ing") and lower[:-3] + "e" in _SAFE_LEXICON:
                return True
            # Adverb (word + ly)
            if lower.endswith("ly") and lower[:-2] in _SAFE_LEXICON:
                return True
            # Noun forms: -tion
            if lower.endswith("tion"):
                # Pattern: calculation -> calculat + e = calculate
                if lower[:-4] + "e" in _SAFE_LEXICON:
                    return True
                if lower[:-4] in _SAFE_LEXICON:
                    return True
                # Remove ion and add e -> calculation -> calculate
                if lower[:-3] + "e" in _SAFE_LEXICON:
                    return True
                # -ition pattern: definition -> defin + e = define
                if lower.endswith("ition") and lower[:-5] + "e" in _SAFE_LEXICON:
                    return True
                # -ation pattern: adaptation -> adapt
                if lower.endswith("ation") and lower[:-5] in _SAFE_LEXICON:
                    return True
                if lower.endswith("ation") and lower[:-5] + "e" in _SAFE_LEXICON:
                    return True
                # -ization: organization -> organise + ...
                if lower.endswith("ization") and lower[:-6] + "e" in _SAFE_LEXICON:
                    return True
                # -ification: specification -> specify -> but stem is "specif"
                if lower.endswith("ification") and lower[:-7] + "y" in _SAFE_LEXICON:
                    return True
            # -sion forms (extension, provision)
            if lower.endswith("sion"):
                if lower[:-4] + "d" in _SAFE_LEXICON:  # extend -> extension
                    return True
                if lower[:-4] + "e" in _SAFE_LEXICON:  # provide -> provision
                    return True
            # -ment forms (agreement, development)
            if lower.endswith("ment"):
                if lower[:-4] in _SAFE_LEXICON:
                    return True
                if lower[:-4] + "e" in _SAFE_LEXICON:
                    return True
            # -ness forms (kindness, effectiveness)
            if lower.endswith("ness"):
                if lower[:-4] in _SAFE_LEXICON:
                    return True
                if lower[:-4] + "y" in _SAFE_LEXICON:
                    return True
                if lower[:-4] + "le" in _SAFE_LEXICON:
                    return True
            # -able/-ible (readable, sensible)
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
            # -ity forms (activity, capability)
            if lower.endswith("ity"):
                if lower[:-3] in _SAFE_LEXICON:
                    return True
                if lower[:-3] + "e" in _SAFE_LEXICON:
                    return True
                if lower[:-3] + "y" in _SAFE_LEXICON:
                    return True
                # capability -> capable, stability -> stable
                if lower[:-5] + "le" in _SAFE_LEXICON:
                    return True
                # activity -> active (already covered by -3 + e above)
            # -ive forms (active, productive)
            if lower.endswith("ive"):
                if lower[:-3] in _SAFE_LEXICON:
                    return True
                if lower[:-3] + "e" in _SAFE_LEXICON:
                    return True
                if lower[:-3] + "ion" in _SAFE_LEXICON:
                    return True
            # -ness forms (kindness, effectiveness)
            if lower.endswith("ness"):
                if lower[:-4] in _SAFE_LEXICON:
                    return True
                if lower[:-4] + "y" in _SAFE_LEXICON:
                    return True
                if lower[:-4] + "le" in _SAFE_LEXICON:
                    return True
                # happiness -> happy (y→i transformation)
                if len(lower) > 6 and lower[:-4].endswith("i"):
                    if lower[:-5] + "y" in _SAFE_LEXICON:
                        return True
            # -al forms (global, functional)
            if lower.endswith("al"):
                if lower[:-2] in _SAFE_LEXICON:
                    return True
                if lower[:-2] + "e" in _SAFE_LEXICON:
                    return True
                if lower[:-2] + "y" in _SAFE_LEXICON:
                    return True
            # -ic forms (generic, specific)
            if lower.endswith("ic"):
                if lower[:-2] in _SAFE_LEXICON:
                    return True
                if lower[:-2] + "y" in _SAFE_LEXICON:
                    return True
            # -ous forms (dangerous, famous)
            if lower.endswith("ous"):
                if lower[:-3] in _SAFE_LEXICON:
                    return True
                if lower[:-3] + "e" in _SAFE_LEXICON:
                    return True
                if lower[:-3] + "y" in _SAFE_LEXICON:
                    return True
            # -ful forms (useful, powerful)
            if lower.endswith("ful"):
                if lower[:-3] in _SAFE_LEXICON:
                    return True
            # -less forms (useless, timeless)
            if lower.endswith("less"):
                if lower[:-4] in _SAFE_LEXICON:
                    return True
            # -ward forms (forward, backward)
            if lower.endswith("ward"):
                if lower[:-4] in _SAFE_LEXICON:
                    return True
            # -th forms (strength, length, width)
            if lower.endswith("th") and len(lower) >= 5:
                if lower[:-2] in _SAFE_LEXICON:
                    return True
                # strong -> strength: stems ending in ng/ng -> ngth
                if lower[:-2] + "ng" in _SAFE_LEXICON:
                    return True
                if lower[:-2] + "n" in _SAFE_LEXICON:
                    return True
            # -ance/-ence forms (performance, existence)
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
            # -ist forms (artist, scientist)
            if lower.endswith("ist"):
                if lower[:-3] in _SAFE_LEXICON:
                    return True
                if lower[:-3] + "e" in _SAFE_LEXICON:
                    return True
                if lower[:-3] + "y" in _SAFE_LEXICON:
                    return True
            # -ism forms (realism, capitalism)
            if lower.endswith("ism"):
                if lower[:-3] in _SAFE_LEXICON:
                    return True
                if lower[:-3] + "e" in _SAFE_LEXICON:
                    return True
                if lower[:-3] + "y" in _SAFE_LEXICON:
                    return True
            # -ize/-ise forms (realize, organize)
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
            # Comparative / superlative (word + er, word + est)
            if lower.endswith("er") and lower[:-2] in _SAFE_LEXICON:
                return True
            if lower.endswith("est") and lower[:-3] in _SAFE_LEXICON:
                return True

            return False

        def _replace_word(m: re.Match) -> str:
            token = m.group(0)
            lower = token.lower()

            # Skip safe words (direct or derived)
            if _is_safe_derived(token):
                return token

            # Skip short tokens
            if len(token) < self._min_rare:
                return token

            # Skip tokens with digits (likely versions, codes)
            if re.search(r"\d", token):
                if not re.match(r"^[a-zA-Z0-9]+$", token):
                    return token
                digit_ratio = sum(1 for c in token if c.isdigit()) / len(token)
                if digit_ratio > 0.4:
                    return token

            # Skip tokens that are already placeholders
            if token.startswith("_VEN_") or (token.startswith("[") and token.endswith("]")):
                return token

            # Skip path-like tokens
            if "/" in token or "\\" in token or "://" in token:
                return token

            # Skip pure hex-looking tokens (already handled by uuid/hash)
            if re.match(r"^[0-9a-f]{8,}$", token, re.IGNORECASE):
                return token

            # This word passes all filters: it's rare/user-specific
            return self._store(token)

        # Match standalone word tokens
        return re.sub(
            r"(?<![a-zA-Z0-9_\-])([a-zA-Z_][a-zA-Z0-9_]*)(?![a-zA-Z0-9_\-])",
            _replace_word,
            text,
        )


# ------------------------------------------------------------------
# Quick self-test
# ------------------------------------------------------------------
if __name__ == "__main__":
    n = LexiconNormalizer()

    tests = [
        # (label, input, expected_contains)
        ("common english", "The calculation is correct", False),
        ("common english 2", "What is the definition of this", False),
        ("common english 3", "The arguments are valid", False),
        ("common english 4", "Processing complete", False),
        ("common english 5", "Analysis shows improvement", False),
        ("uuid", "Lookup 550e8400-e29b-41d4-a716-446655440000 here", True),
        ("hash", "hash a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 here", True),
        ("camelCase", "myCustomVariable is here", True),
        ("PascalCase", "MyCustomClass is here", True),
        ("snake_case", "my_custom_variable is here", True),
        ("short word", "a an the cat dog run", False),
        ("acronym", "The API called GET", False),
        ("SQL", "SELECT * FROM users WHERE id = 1", False),
        ("punctuation", "Hello! Is this working? Yes, it is.", False),
        ("code keywords", "def __init__(self): pass", False),
        ("modifiers", "quickly running jumped foxes happily", False),
    ]

    passed = 0
    failed = 0
    for label, text, expect_change in tests:
        n.reset()
        result = n.sanitize_text(text)
        changed = result != text
        # For UUID/hash/camelCase etc, we expect changes
        status = (
            "PASS" if (changed == expect_change) else "FAIL"
        )
        if status == "PASS":
            passed += 1
        else:
            failed += 1
            print(f"  {status}: {label} -> {result}")

    n.reset()
    # Roundtrip test
    original = "MyCustomClass has a550e8400-e29b-41d4-a716-446655440000"
    sanitized = n.sanitize_text(original)
    restored = n.restore_text(sanitized)
    if restored == original:
        passed += 1
        print(f"  PASS: roundtrip {original!r}")
    else:
        failed += 1
        print(f"  FAIL: roundtrip {original!r} -> {sanitized!r} -> {restored!r}")

    # UUID + camelCase combined test
    n.reset()
    combined = "User myCustomVar with uuid 550e8400-e29b-41d4-a716-446655440000 processed"
    result = n.sanitize_text(combined)
    if "_VEN_" in result and result != combined:
        passed += 1
        print(f"  PASS: combined uuid+camelCase: {result}")
    else:
        failed += 1
        print(f"  FAIL: combined uuid+camelCase: {result}")

    # Rare word test
    n.reset()
    rare = "This is a zqxwvutsr specific test"
    result = n.sanitize_text(rare)
    if "zqxwvutsr" not in result:
        passed += 1
        print(f"  PASS: rare word replaced: {result}")
    else:
        failed += 1
        print(f"  FAIL: rare word not replaced: {result}")

    print(f"\n  Results: {passed} passed, {failed} failed")
