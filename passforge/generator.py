"""Core password and secret generation logic."""

import secrets
import string
import math
import hashlib
import base64
import re
from typing import Optional

# Character sets
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"
AMBIGUOUS = "0O1lI"

# Wordlist for passphrases (EFF large wordlist subset)
WORDLIST = [
    "abandon","ability","able","about","above","absent","absorb","abstract",
    "absurd","abuse","access","accident","account","accuse","achieve","acid",
    "acoustic","acquire","across","action","actor","actual","adapt","add",
    "addict","address","adjust","admit","adult","advance","advice","aerobic",
    "afford","afraid","again","agent","agree","ahead","aim","airport","aisle",
    "alarm","album","alcohol","alert","alien","alley","allow","almost","alone",
    "alpine","already","also","alter","always","amateur","amazing","among",
    "amount","amused","analyst","anchor","anger","angle","angry","animal",
    "ankle","announce","annual","another","answer","antenna","antique","anxiety",
    "any","apart","apology","appear","apple","approve","april","arcade","arctic",
    "area","arena","argue","arm","armor","army","around","arrange","arrest",
    "arrive","arrow","art","artefact","artist","artwork","ask","aspect","assault",
    "asset","assist","assume","asthma","athlete","atom","attack","attend","attract",
    "auction","audit","august","aunt","author","auto","autumn","average","avocado",
    "avoid","awake","aware","awesome","awful","awkward","axis","baby","balance",
    "bamboo","banana","banner","barely","bargain","barrel","base","basic","battle",
    "beach","bean","beauty","become","beef","begin","behave","behind","believe",
    "below","belt","bench","benefit","best","betray","better","between","beyond",
    "bicycle","bid","bike","bind","biology","bird","birth","bitter","black","blade",
    "blame","blanket","blast","bleak","bless","blind","blood","blossom","blouse",
    "blue","blur","blush","board","boat","body","boil","bomb","bone","book","boost",
    "border","boring","borrow","boss","bottom","bounce","box","boy","bracket","brain",
    "brand","brave","bread","breeze","brick","bridge","brief","bright","bring",
    "brisk","broccoli","broken","bronze","broom","brother","brown","brush","bubble",
    "buddy","budget","buffalo","build","bulb","bulk","bullet","bundle","bunker",
    "burden","burger","burst","bus","business","busy","butter","buyer","buzz",
    "cabbage","cabin","cable","cactus","cage","cake","call","calm","camera","camp",
    "canal","cancel","candy","cannon","canoe","canvas","canyon","capable","capital",
    "captain","carbon","carpet","carry","cart","case","cash","casino","castle",
    "casual","catalog","catch","category","cattle","caught","cause","caution","cave",
    "ceiling","celery","cement","census","century","cereal","certain","chair",
    "chaos","chapter","charge","chase","cheap","check","cheese","chef","cherry",
    "chest","chicken","chief","child","chimney","choice","choose","chronic","chuckle",
    "chunk","cigar","cinema","circle","citizen","city","civil","claim","clap",
    "clarify","claw","clay","clean","clerk","clever","click","client","cliff",
    "climb","clinic","clip","clock","clog","close","cloth","cloud","clown","club",
    "clump","cluster","clutch","coach","coast","coconut","code","coffee","coil",
    "coin","collect","color","column","combine","come","comfort","comic","common",
    "company","concert","conduct","confirm","congress","connect","consider","control",
    "convince","cook","cool","copper","copy","coral","core","corn","correct","cost",
    "cotton","couch","country","couple","course","cousin","cover","coyote","crack",
    "cradle","craft","cram","crane","crash","crater","crawl","crazy","cream","credit",
    "creek","crew","cricket","crime","crisp","critic","cross","crouch","crowd",
    "crucial","cruel","cruise","crumble","crush","cry","crystal","cube","culture",
    "cup","cupboard","curious","current","curtain","curve","cushion","custom","cute",
    "cycle","dad","damage","damp","dance","danger","daring","dash","daughter","dawn",
    "deal","debate","debris","decade","december","decide","decline","decorate",
    "decrease","deer","defense","define","defy","degree","delay","deliver","demand",
    "demise","denial","dentist","deny","depart","depend","deposit","depth","deputy",
    "derive","describe","desert","design","desk","despair","destroy","detail",
    "detect","develop","device","devote","diagram","dial","diamond","diary","dice",
    "diesel","differ","digital","dignity","dilemma","dinner","dinosaur","direct",
    "dirt","disagree","discover","disease","dish","dismiss","disorder","display",
    "distance","divert","divide","divorce","dizzy","doctor","document","double",
    "dove","draft","dragon","drama","drastic","draw","dream","dress","drift","drink",
    "drip","drive","drop","drum","dry","duck","dumb","durable","dust","dutch","duty",
    "eager","early","earn","earth","easily","east","echo","edge","effort","eight",
    "either","elbow","elder","electric","elegant","element","elephant","elite",
    "else","embark","embody","emerge","emotion","employ","empower","empty","enable",
    "enact","endless","endorse","enemy","enforce","engage","engine","enhance",
    "enjoy","enlist","enough","ensure","enter","entire","entry","equal","escape",
    "essay","eternal","ethics","evidence","evil","evolve","exact","example","excess",
    "exchange","excite","exclude","exercise","exhaust","exhibit","exile","exist",
    "exit","exotic","expand","expire","explain","expose","express","extend","extra",
    "fabric","face","faculty","faint","faith","false","famous","fancy","fantasy",
    "farm","fashion","fatal","father","fatigue","fault","favorite","feature","faint",
    "february","federal","feel","female","fence","festival","fetch","fever","field",
    "figure","file","film","filter","final","finger","finish","fire","first","fiscal",
    "fish","fit","fitness","fix","flag","flame","flash","flat","flavor","flee",
    "flight","float","flock","floor","flower","fluid","flush","fly","foam","focus",
    "fog","foil","follow","food","force","forest","forget","fork","fortune","forum",
    "forward","fossil","foster","found","fox","fragile","frame","frequent","fresh",
    "fridge","friend","front","frost","frown","frozen","fruit","fuel","fun","funny",
    "furnace","fury","future","gadget","gain","galaxy","gallery","game","gap","garden",
    "garlic","garment","gasp","gate","gather","gauge","gaze","general","genius",
    "genre","gentle","genuine","gesture","ghost","giant","gift","giggle","ginger",
    "giraffe","girl","give","glad","glance","glare","glass","gloom","glove","glow",
    "glue","goat","goddess","gold","good","goose","gorilla","gospel","grace","grain",
    "grape","grass","gravity","great","green","grid","grief","grit","grocery","group",
    "grow","grunt","guard","guide","guilt","guitar","gun","habit","hair","half","hammer",
    "hamster","hand","happy","harsh","harvest","have","hawk","hazard","head","health",
    "heart","heavy","hedgehog","height","hello","helmet","help","hero","hidden","high",
    "hill","hint","hobby","hockey","hold","holiday","hollow","home","honey","hood",
    "hope","horn","hospital","host","hour","hover","hub","huge","humble","humor",
    "hurdle","hurry","hurt","hybrid","ice","icon","ignore","illegal","image","imitate",
    "immune","impact","impose","improve","impulse","inbox","include","income","index",
    "indicate","indoor","industry","infant","inflict","inform","inhale","inject",
    "inner","innocent","input","inquiry","insect","inside","inspire","install",
    "intact","interest","into","invest","invite","involve","island","isolate","issue",
    "item","ivory","jacket","jaguar","jealous","jeans","jelly","jewel","job","join",
    "journey","judge","juice","jump","jungle","junior","junk","just","kangaroo",
    "keen","keep","ketchup","key","kick","kid","kingdom","kiss","kit","kitchen",
    "kite","kitten","kiwi","knee","knife","knock","know","lab","ladder","lamp",
    "language","laptop","large","later","laugh","laundry","lava","lawn","lawsuit",
    "layer","lazy","leader","learn","leave","legal","legend","lemon","length","lesson",
    "letter","level","liar","liberty","library","license","life","lift","light",
    "limit","link","lion","liquid","list","little","lizard","load","loan","lobster",
    "lock","logic","lonely","long","loop","lottery","loud","lounge","love","loyal",
    "lucky","luggage","lumber","lunar","lunch","machine","magic","magnet","mango",
    "mansion","manual","maple","marble","margin","marine","market","marriage","mask",
    "master","match","material","math","matter","maximum","maze","measure","medal",
    "media","melody","melt","member","memory","mention","menu","mercy","mesh","message",
    "metal","method","middle","midnight","milk","million","mimic","mind","minimum",
    "minor","minute","miracle","miss","mixture","mobile","model","modify","moment",
    "monitor","monkey","monster","month","moon","moral","more","morning","mosquito",
    "mother","motion","mountain","mouse","move","movie","much","mule","multiply",
    "muscle","museum","mushroom","music","must","mutual","myself","mystery","naive",
    "name","napkin","narrow","nation","nature","near","neck","need","negative","neglect",
    "nephew","nerve","network","neutral","never","news","next","nice","night","noble",
    "noise","nominee","noodle","normal","north","notable","notice","novel","number",
    "nurse","object","oblige","obscure","obtain","ocean","offer","office","often",
    "olive","olympic","omit","once","open","opera","oppose","option","orange","orbit",
    "orchard","order","ordinary","organ","orient","original","orphan","ostrich",
    "outside","oval","owner","oxygen","oyster","ozone","panda","panel","panic","panther",
    "paper","parade","parent","park","parrot","party","pass","patient","patrol","pause",
    "pave","payment","peace","peanut","peasant","pelican","penalty","pencil","people",
    "pepper","perfect","permit","person","phone","photo","phrase","physical","piano",
    "picnic","picture","piece","pigeon","pilot","pink","pipe","pistol","pitch","pizza",
    "place","planet","plastic","plate","play","please","pledge","plunge","poem","poet",
    "point","polar","pole","police","pond","pony","pool","popular","portion","position",
    "possible","post","potato","poverty","powder","power","practice","praise","predict",
    "prefer","prepare","present","pretty","prevent","price","pride","primary","print",
    "prison","private","problem","process","produce","project","promote","proof",
    "property","protect","proud","provide","public","pudding","pull","pulp","punch",
    "pupil","purchase","purpose","push","put","puzzle","pyramid","quality","quantum",
    "quarter","question","quick","quit","quote","rabbit","raccoon","race","rack","radar",
    "radio","rage","rail","rain","raise","rally","ramp","ranch","random","range",
    "rapid","rare","rate","rather","raven","reach","ready","real","reason","rebel",
    "rebuild","recall","receive","recipe","record","recycle","reduce","reflect","reform",
    "refuse","region","regret","regular","reject","relax","release","relief","remain",
    "remove","render","repair","repeat","replace","report","require","rescue","resist",
    "resource","response","result","retire","retreat","return","reveal","reward","rhythm",
    "ribbon","ride","ridge","rifle","right","rigid","ring","riot","ripple","risk","ritual",
    "rival","river","road","robot","robust","rocket","romance","roof","rookie","route",
    "royal","rubber","rude","rug","rule","runway","rural","sad","saddle","sadness",
    "safe","sail","salad","salmon","salon","salt","salute","same","sample","sand",
    "satisfy","sauce","sausage","save","scale","scan","scatter","scene","scheme","school",
    "science","scissors","scorpion","scout","scrap","screen","script","scrub","search",
    "season","seat","second","secret","section","security","select","sell","seminar",
    "senior","sense","series","service","seven","shadow","shaft","shallow","share",
    "sheep","shell","sheriff","shield","shift","shine","ship","short","shoulder","shove",
    "shrimp","shrug","shuffle","siege","silver","simple","since","sing","sister","skill",
    "skull","slab","slam","sleep","slender","slice","slide","slight","slim","slogan",
    "slow","slush","small","smart","smile","smoke","smooth","snack","snake","snap",
    "sniff","snow","soap","soccer","social","sock","solar","solution","solve","someone",
    "sorry","sort","soul","sound","source","south","space","spare","spatial","spawn",
    "speak","special","speed","sphere","spice","spider","spike","spin","spirit","split",
    "spoil","sponsor","spray","spread","spring","squad","stable","stadium","staff",
    "stage","stairs","stamp","stand","start","state","stay","steak","steel","stem",
    "step","stereo","stick","still","sting","stock","stomach","stone","stop","store",
    "storm","strategy","street","strike","strong","struggle","student","stuff","stumble",
    "style","subject","submit","subway","success","such","sudden","suffer","suggest",
    "suit","summer","super","supply","supreme","surprise","sustain","swallow","swamp",
    "swap","swear","sweet","swift","swim","swing","switch","sword","symbol","symptom",
    "table","tackle","tag","tail","talent","tango","target","task","tattoo","teach",
    "team","tell","tennis","term","test","text","thank","theory","throw","ticket",
    "tiger","timber","time","tiny","tired","title","toast","together","toilet","token",
    "tomorrow","tooth","tornado","tourist","toward","tower","town","trade","traffic",
    "tragic","train","transfer","travel","tree","trend","trial","trick","trigger","trim",
    "trip","trophy","trouble","truck","truly","trumpet","trust","truth","tunnel","turkey",
    "turn","turtle","twelve","twice","typical","umbrella","unable","uniform","unique",
    "unknown","until","unusual","unveil","update","upgrade","uphold","upper","upset",
    "urban","useful","useless","usual","utility","vacant","vacuum","valid","valley",
    "valve","vanilla","various","vendor","venture","verb","verify","version","very",
    "viable","video","view","village","vintage","violin","virtual","visit","visual",
    "vital","vivid","vocal","voice","volume","vote","voyage","wage","wagon","wait",
    "walk","wall","walnut","warm","warrior","water","wave","way","wealth","weapon",
    "wear","weasel","weather","web","wedding","weekend","weird","welcome","west",
    "wheel","where","whip","whisper","wide","width","wife","wild","will","window",
    "wing","winter","wire","wisdom","wish","witness","wolf","woman","wonder","wood",
    "wool","word","world","worry","worth","wrap","wreck","wrestle","write","yard",
    "year","young","youth","zebra","zero","zone","zoo"
]


def _entropy(charset_size: int, length: int) -> float:
    """Calculate password entropy in bits."""
    if charset_size <= 0 or length <= 0:
        return 0.0
    return length * math.log2(charset_size)


def _crack_time_label(entropy: float) -> str:
    """Estimate crack time label from entropy."""
    # Assume 10 billion guesses/second (GPU cluster)
    guesses_per_second = 1e10
    combinations = 2 ** entropy
    seconds = combinations / guesses_per_second / 2  # average
    if seconds < 1:
        return "instant"
    elif seconds < 60:
        return f"{seconds:.0f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.0f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.0f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.0f} days"
    elif seconds < 3153600000:
        return f"{seconds/31536000:.0f} years"
    else:
        years = seconds / 31536000
        if years < 1e6:
            return f"{years/1e3:.0f} thousand years"
        elif years < 1e9:
            return f"{years/1e6:.0f} million years"
        else:
            return f"{years/1e9:.0f} billion+ years"


def _strength_label(entropy: float) -> tuple[str, str]:
    """Return (label, color) for entropy strength."""
    if entropy < 28:
        return "Very Weak", "red"
    elif entropy < 36:
        return "Weak", "orange1"
    elif entropy < 60:
        return "Moderate", "yellow"
    elif entropy < 80:
        return "Strong", "green"
    elif entropy < 120:
        return "Very Strong", "bright_green"
    else:
        return "Extreme", "bold bright_green"


def generate_password(
    length: int = 16,
    uppercase: bool = True,
    lowercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
    exclude_chars: str = "",
    min_uppercase: int = 0,
    min_lowercase: int = 0,
    min_digits: int = 0,
    min_symbols: int = 0,
) -> str:
    """Generate a cryptographically secure random password."""
    charset = ""
    required = []

    if lowercase:
        chars = LOWERCASE
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS)
        if exclude_chars:
            chars = "".join(c for c in chars if c not in exclude_chars)
        charset += chars
        for _ in range(min_lowercase):
            required.append(secrets.choice(chars))

    if uppercase:
        chars = UPPERCASE
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS)
        if exclude_chars:
            chars = "".join(c for c in chars if c not in exclude_chars)
        charset += chars
        for _ in range(min_uppercase):
            required.append(secrets.choice(chars))

    if digits:
        chars = DIGITS
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS)
        if exclude_chars:
            chars = "".join(c for c in chars if c not in exclude_chars)
        charset += chars
        for _ in range(min_digits):
            required.append(secrets.choice(chars))

    if symbols:
        chars = SYMBOLS
        if exclude_chars:
            chars = "".join(c for c in chars if c not in exclude_chars)
        charset += chars
        for _ in range(min_symbols):
            required.append(secrets.choice(chars))

    if not charset:
        raise ValueError("At least one character set must be enabled.")

    remaining_length = length - len(required)
    if remaining_length < 0:
        raise ValueError("Password length too short for required character minimums.")

    password_chars = required + [secrets.choice(charset) for _ in range(remaining_length)]

    # Shuffle using Fisher-Yates via secrets
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


def generate_passphrase(
    words: int = 4,
    separator: str = "-",
    capitalize: bool = False,
    include_number: bool = True,
) -> str:
    """Generate a memorable passphrase from wordlist."""
    chosen = [secrets.choice(WORDLIST) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    phrase = separator.join(chosen)
    if include_number:
        phrase += separator + str(secrets.randbelow(9000) + 1000)
    return phrase


def generate_pin(length: int = 6) -> str:
    """Generate a numeric PIN."""
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def generate_token(length: int = 32, format: str = "hex") -> str:
    """Generate a secure random token."""
    if format == "hex":
        return secrets.token_hex(length // 2)
    elif format == "urlsafe":
        return secrets.token_urlsafe(length)
    elif format == "base64":
        raw = secrets.token_bytes(length)
        return base64.b64encode(raw).decode()
    elif format == "alphanumeric":
        charset = string.ascii_letters + string.digits
        return "".join(secrets.choice(charset) for _ in range(length))
    elif format == "uuid":
        import uuid
        return str(uuid.uuid4())
    else:
        raise ValueError(f"Unknown token format: {format}")


def analyze_password(password: str) -> dict:
    """Analyze password strength and return metrics."""
    length = len(password)

    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    has_ambiguous = any(c in AMBIGUOUS for c in password)

    # Calculate actual charset size
    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += len(SYMBOLS)

    entropy = _entropy(charset_size, length)
    strength_label, strength_color = _strength_label(entropy)
    crack_time = _crack_time_label(entropy)

    # Check for common patterns
    patterns = []
    if re.search(r"(.)\1{2,}", password):
        patterns.append("repeated characters")
    if re.search(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)", password.lower()):
        patterns.append("sequential patterns")
    if re.search(r"(qwerty|asdf|zxcv|password|pass|admin|login|user|welcome)", password.lower()):
        patterns.append("common words/sequences")

    # SHA-1 hash for HIBP check (first 5 chars only shown)
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()

    return {
        "length": length,
        "entropy": entropy,
        "charset_size": charset_size,
        "has_lowercase": has_lower,
        "has_uppercase": has_upper,
        "has_digits": has_digit,
        "has_symbols": has_symbol,
        "has_ambiguous": has_ambiguous,
        "strength": strength_label,
        "strength_color": strength_color,
        "crack_time": crack_time,
        "patterns": patterns,
        "sha1_prefix": sha1_hash[:5],
        "sha1_suffix": sha1_hash[5:],
    }


def check_hibp(sha1_prefix: str, sha1_suffix: str) -> Optional[int]:
    """Check Have I Been Pwned API. Returns breach count or None on error."""
    import urllib.request
    try:
        url = f"https://api.pwnedpasswords.com/range/{sha1_prefix}"
        req = urllib.request.Request(url, headers={"User-Agent": "passforge/0.1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read().decode()
        for line in data.splitlines():
            suffix, count = line.split(":")
            if suffix.upper() == sha1_suffix.upper():
                return int(count)
        return 0
    except Exception:
        return None


def password_entropy_for_charset(charset_size: int, length: int) -> float:
    return _entropy(charset_size, length)
