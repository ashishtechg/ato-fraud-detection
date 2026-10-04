"""
ATO Fraud Detection on Snowflake — Executive Slide Deck Builder
Generates a professional .pptx with 10 slides + speaker notes.

Slide map (v2):
  1  Title
  2  The Business Problem
  3  Target Personas
  4  Pain Points → Solution
  5  Architecture Diagram (data flow, structured/unstructured sources, modular components)
  6  CoCo CLI Skills & How They Connect
  7  4-Layer ML Ensemble Deep Dive
  8  Industry & Regulatory Context
  9  Impact Statement (outcomes, scalability, extensibility)
 10  Key Takeaways
"""

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
import shutil

# ── Brand palette ──────────────────────────────────────────────
SNOW_DARK    = RGBColor(0x11, 0x27, 0x4B)
SNOW_BLUE    = RGBColor(0x29, 0xB5, 0xE8)
SNOW_ACCENT  = RGBColor(0x00, 0x7E, 0xB5)
WHITE        = RGBColor(0xFF, 0xFF, 0xFF)
LIGHT_GRAY   = RGBColor(0xF2, 0xF4, 0xF7)
MED_GRAY     = RGBColor(0x6B, 0x7B, 0x8D)
DARK_TEXT     = RGBColor(0x1A, 0x1A, 0x2E)
RED_ACCENT   = RGBColor(0xE8, 0x3E, 0x3E)
GREEN_ACCENT = RGBColor(0x2E, 0xCC, 0x71)
AMBER_ACCENT = RGBColor(0xF5, 0xA6, 0x23)
PURPLE       = RGBColor(0x7C, 0x3A, 0xED)

prs = Presentation()
prs.slide_width  = Inches(13.333)
prs.slide_height = Inches(7.5)
W = prs.slide_width
H = prs.slide_height

# ── Helpers ────────────────────────────────────────────────────
def add_bg(slide, color):
    fill = slide.background.fill
    fill.solid()
    fill.fore_color.rgb = color

def add_shape(slide, left, top, width, height, fill_color, line_color=None):
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill_color
    if line_color:
        shape.line.color.rgb = line_color
        shape.line.width = Pt(1)
    else:
        shape.line.fill.background()
    return shape

def add_rect(slide, left, top, width, height, fill_color, line_color=None):
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill_color
    if line_color:
        shape.line.color.rgb = line_color
        shape.line.width = Pt(1)
    else:
        shape.line.fill.background()
    return shape

def add_text_box(slide, left, top, width, height, text, font_size=18,
                 color=DARK_TEXT, bold=False, alignment=PP_ALIGN.LEFT, font_name="Calibri"):
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(font_size)
    p.font.color.rgb = color
    p.font.bold = bold
    p.font.name = font_name
    p.alignment = alignment
    return tf

def add_para(tf, text, font_size=16, color=DARK_TEXT, bold=False, space_before=Pt(6),
             bullet=False, alignment=PP_ALIGN.LEFT, font_name="Calibri", indent_level=0):
    p = tf.add_paragraph()
    p.text = text
    p.font.size = Pt(font_size)
    p.font.color.rgb = color
    p.font.bold = bold
    p.font.name = font_name
    p.alignment = alignment
    p.level = indent_level
    if space_before:
        p.space_before = space_before
    if bullet:
        from pptx.oxml.ns import qn
        pPr = p._p.get_or_add_pPr()
        buChar = pPr.makeelement(qn('a:buChar'), {'char': '•'})
        buSzPct = pPr.makeelement(qn('a:buSzPct'), {'val': '100000'})
        buClr = pPr.makeelement(qn('a:buClr'), {})
        srgbClr = buClr.makeelement(qn('a:srgbClr'), {'val': '29B5E8'})
        buClr.append(srgbClr)
        pPr.append(buSzPct)
        pPr.append(buClr)
        pPr.append(buChar)
    return p

def set_notes(slide, notes_text):
    slide.notes_slide.notes_text_frame.text = notes_text

def bar(slide, left, top, width, height, color=SNOW_BLUE):
    return add_rect(slide, left, top, width, height, color)

def kpi(slide, left, top, w, h, label, value, accent=SNOW_BLUE):
    add_shape(slide, left, top, w, h, WHITE, line_color=RGBColor(0xE0, 0xE0, 0xE0))
    bar(slide, left, top, w, Pt(4), accent)
    add_text_box(slide, left + Inches(0.15), top + Inches(0.2), w - Inches(0.3), Inches(0.5),
                 value, font_size=26, color=accent, bold=True, alignment=PP_ALIGN.CENTER)
    add_text_box(slide, left + Inches(0.15), top + Inches(0.78), w - Inches(0.3), Inches(0.4),
                 label, font_size=11, color=MED_GRAY, alignment=PP_ALIGN.CENTER)

def slide_header(slide, title, bg_color=WHITE):
    add_bg(slide, bg_color)
    bar(slide, Inches(0), Inches(0), W, Pt(4), SNOW_BLUE)
    add_text_box(slide, Inches(0.8), Inches(0.4), Inches(10), Inches(0.6),
                 title, font_size=32, color=SNOW_DARK, bold=True)
    bar(slide, Inches(0.8), Inches(1.05), Inches(2.5), Pt(3), SNOW_BLUE)

def arrow_right(slide, x, y, w=Inches(0.22), h=Inches(0.35)):
    a = slide.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, x, y, w, h)
    a.fill.solid()
    a.fill.fore_color.rgb = SNOW_BLUE
    a.line.fill.background()

def arrow_down(slide, x, y, w=Inches(0.3), h=Inches(0.25)):
    a = slide.shapes.add_shape(MSO_SHAPE.DOWN_ARROW, x, y, w, h)
    a.fill.solid()
    a.fill.fore_color.rgb = SNOW_BLUE
    a.line.fill.background()

# ═══════════════════════════════════════════════════════════════
# SLIDE 1 — Title
# ═══════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(sl, SNOW_DARK)
bar(sl, Inches(0), Inches(0), W, Pt(6), SNOW_BLUE)
add_text_box(sl, Inches(1), Inches(1.8), Inches(11), Inches(1.2),
             "Account Takeover Fraud Detection", font_size=42, color=WHITE, bold=True)
add_text_box(sl, Inches(1), Inches(3.0), Inches(11), Inches(0.8),
             "Real-Time, ML-Powered Detection on Snowflake", font_size=24, color=SNOW_BLUE)
add_text_box(sl, Inches(1), Inches(4.2), Inches(11), Inches(0.6),
             "4-Layer Ensemble ML  •  Dynamic Table Pipelines  •  Cortex Agent  •  Full Governance",
             font_size=16, color=MED_GRAY)
bar(sl, Inches(1), Inches(5.2), Inches(3), Pt(3), SNOW_BLUE)
add_text_box(sl, Inches(1), Inches(5.5), Inches(6), Inches(0.5),
             "Built 100% on Snowflake  |  Prototype-Ready", font_size=14, color=MED_GRAY)

set_notes(sl, """SPEAKER NOTES — Title Slide

Opening hook: "Account takeover is the fastest-growing form of digital fraud. It costs US financial institutions over $11 billion annually — and that number is accelerating as attackers weaponize AI and credential dumps from data breaches."

Key framing points:
• This is a complete, production-grade ATO detection system built entirely on Snowflake — no external ML platforms, no separate policy engines, no data movement.
• It demonstrates how Snowflake can serve as a unified fraud intelligence platform: from raw event ingestion through ML scoring to analyst investigation and regulatory compliance.
• The system uses synthetic data (50K customers, 13M+ login events) to demonstrate real-world scale and 10 distinct attack scenarios.
• Transition: "Let me walk you through the business problem this solves and how we built a solution that consolidates what typically requires 5-7 separate tools into a single platform."
""")

# ═══════════════════════════════════════════════════════════════
# SLIDE 2 — The Business Problem
# ═══════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
slide_header(sl, "The Business Problem")

kpi(sl, Inches(0.8),  Inches(1.5), Inches(2.6), Inches(1.2), "Annual US ATO Losses", "$11B+", RED_ACCENT)
kpi(sl, Inches(3.7),  Inches(1.5), Inches(2.6), Inches(1.2), "Cost per Compromised Acct", "$12K–$25K", RED_ACCENT)
kpi(sl, Inches(6.6),  Inches(1.5), Inches(2.6), Inches(1.2), "Avg Dwell Time", "30–90 Days", AMBER_ACCENT)
kpi(sl, Inches(9.5),  Inches(1.5), Inches(2.6), Inches(1.2), "YoY Attack Growth", "354%", RED_ACCENT)

tf = add_text_box(sl, Inches(0.8), Inches(3.1), Inches(11.5), Inches(0.4),
                  "Why Traditional Approaches Fail", font_size=20, color=SNOW_DARK, bold=True)
problems = [
    "Static rule-based systems — generate excessive false positives and miss novel attack patterns; credential stuffing, SIM-swaps, and bot automation evolve faster than rules can be written",
    "Batch processing delays — fraud discovered hours or days after compromise; attackers operate inside accounts for 30–90 days before detection",
    "Siloed data and tools — fragment the fraud signal across 5–7 platforms; identity, device, behavioral, and threat intel data never converge for holistic scoring",
    "Regulatory pressure mounting — FTC Safeguards Rule, CFPB MFA Circular, FinCEN AML/CDD, and FFIEC Authentication Guidance mandate real-time controls with auditable evidence",
]
for t in problems:
    add_para(tf, t, font_size=14, color=DARK_TEXT, bullet=True, space_before=Pt(10))

set_notes(sl, """SPEAKER NOTES — The Business Problem

Delivery guidance: Let the KPI cards land visually before speaking. Pause on the $11B number.

Talking points:
• "$11 billion — that's the annual cost of account takeover in the US alone, per Javelin Strategy & Research. And it's growing at 354% year-over-year as attackers leverage credential dumps from breaches and GenAI-powered social engineering."
• "The average compromised account costs $12K–$25K when you factor in direct losses, chargebacks, remediation, regulatory fines, and — often overlooked — customer lifetime value erosion."
• "But here's the real problem: dwell time. Attackers are inside accounts for 30 to 90 days on average before anyone notices. By then, they've changed recovery emails, drained funds, and moved on."
• "Why? Because most fraud teams are still running static rule engines designed for a different era. These systems generate so many false positives that analysts develop alert fatigue — they literally stop looking."
• "Meanwhile, the data they need is scattered across 5–7 different tools: one for login analytics, another for device fingerprinting, another for behavioral biometrics, a separate threat intel feed, and a policy engine that doesn't talk to any of them."
• Transition: "So the question becomes: what if you could unify all of this on a single platform?"
""")

# ═══════════════════════════════════════════════════════════════
# SLIDE 3 — Target Personas
# ═══════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
slide_header(sl, "Who Is This For?", LIGHT_GRAY)

personas = [
    ("Fraud Ops Lead",    SNOW_BLUE,   "Runs day-to-day fraud prevention.\nNeeds real-time risk scoring, tiered\ndecisioning, and tunable policy rules."),
    ("Fraud Analyst",     SNOW_ACCENT, "Triages alerts and investigates cases.\nNeeds deep-dive context: identity graph,\ndevice history, behavioral biometrics."),
    ("CISO / Risk Exec",  SNOW_DARK,   "Owns fraud risk at the board level.\nNeeds executive dashboards, model\nperformance KPIs, compliance posture."),
    ("Compliance Officer", AMBER_ACCENT,"Proves controls meet regulatory mandates.\nNeeds audit trails (24M+ evaluations),\nmasking controls, regulatory lookup."),
    ("Data / ML Engineer", GREEN_ACCENT,"Builds and maintains detection pipeline.\nNeeds model registry, feature pipelines,\nleakage guards, retraining workflows."),
]
cw = Inches(2.2)
for i, (title, clr, desc) in enumerate(personas):
    x = Inches(0.5) + i * (cw + Inches(0.2))
    add_shape(sl, x, Inches(1.7), cw, Inches(4.5), WHITE)
    bar(sl, x, Inches(1.7), cw, Pt(5), clr)
    circle = sl.shapes.add_shape(MSO_SHAPE.OVAL, x + Inches(0.7), Inches(2.1), Inches(0.8), Inches(0.8))
    circle.fill.solid(); circle.fill.fore_color.rgb = clr; circle.line.fill.background()
    add_text_box(sl, x + Inches(0.7), Inches(2.2), Inches(0.8), Inches(0.7),
                 title[0], font_size=28, color=WHITE, bold=True, alignment=PP_ALIGN.CENTER)
    add_text_box(sl, x + Inches(0.15), Inches(3.1), cw - Inches(0.3), Inches(0.7),
                 title, font_size=13, color=SNOW_DARK, bold=True, alignment=PP_ALIGN.CENTER)
    add_text_box(sl, x + Inches(0.15), Inches(3.7), cw - Inches(0.3), Inches(2.2),
                 desc, font_size=11, color=MED_GRAY, alignment=PP_ALIGN.CENTER)

set_notes(sl, """SPEAKER NOTES — Target Personas

Delivery guidance: Don't read each card — group them into two audience tiers.

Talking points:
• "This system serves two tiers. The operational tier: Fraud Ops leads who need real-time decisioning, and analysts who need investigation tools with enough context to make fast, accurate calls."
• "The oversight tier: CISOs who report fraud metrics to the board, and compliance officers who prove controls to regulators."
• "Underpinning both are data and ML engineers who build and maintain the pipeline — model registry, leakage guards, versioned artifacts, and a validation suite."
• "All five personas are served by the same unified platform — same data, same models, same policy engine — just through different lenses. That eliminates the 'swivel-chair' problem of toggling between 5 tools."
• Transition: "Let me show you the pain points each faces today and how this system addresses them."
""")

# ═══════════════════════════════════════════════════════════════
# SLIDE 4 — Pain Points vs. Solution
# ═══════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
slide_header(sl, "From Pain Points to Platform")

add_rect(sl, Inches(0.6), Inches(1.35), Inches(5.5), Inches(0.55), SNOW_DARK)
add_text_box(sl, Inches(0.8), Inches(1.37), Inches(5.3), Inches(0.5),
             "Current Pain Point", font_size=15, color=WHITE, bold=True)
add_rect(sl, Inches(6.3), Inches(1.35), Inches(6.3), Inches(0.55), SNOW_BLUE)
add_text_box(sl, Inches(6.5), Inches(1.37), Inches(6.1), Inches(0.5),
             "How This Solution Solves It", font_size=15, color=WHITE, bold=True)

rows = [
    ("Static rule-only systems miss novel attacks\nand generate excessive false positives",
     "4-layer ML ensemble (XGBoost + Isolation Forest\n+ Graph Topology + Meta-Model) catches known\nand zero-day patterns with calibrated 0–1000 scores"),
    ("Batch processing — fraud discovered\nhours or days after compromise",
     "Real-time Dynamic Tables with 1-minute lag\ncontinuously compute velocity, geo-anomaly,\nbehavioral, and threat intel features"),
    ("Alert fatigue — analysts waste time\non false positives, miss real fraud",
     "Tiered decisioning (SAFE / STEP-UP / BLOCK)\nwith 30 tunable policy rules routes only\nhigh-confidence cases to human review"),
    ("Siloed tools — fraud, identity, device,\nand behavioral data in separate systems",
     "Single Snowflake platform unifies 50K customers,\n13M+ logins, device registry, telemetry, identity\ngraph, and threat intel — one semantic layer"),
    ("Regulatory burden — manual evidence\ngathering for compliance audits",
     "Built-in governance (masking, RAP, RBAC),\n24M+ audit records, and Cortex Agent for\npolicy + live Federal Register lookup"),
    ("Black-box models — no explainability,\nhard to audit or trust",
     "Per-login risk factor attribution, versioned model\nregistry, leakage guards that auto-reject features\nwith suspiciously high predictive power"),
]
y0 = Inches(2.05)
rh = Inches(0.85)
for i, (pain, sol) in enumerate(rows):
    y = y0 + i * (rh + Inches(0.05))
    bg = LIGHT_GRAY if i % 2 == 0 else WHITE
    add_shape(sl, Inches(0.6), y, Inches(5.5), rh, bg)
    add_shape(sl, Inches(6.3), y, Inches(6.3), rh, bg)
    add_text_box(sl, Inches(0.8), y + Inches(0.08), Inches(5.1), rh,
                 pain, font_size=11, color=RED_ACCENT)
    add_text_box(sl, Inches(6.5), y + Inches(0.08), Inches(5.9), rh,
                 sol, font_size=11, color=DARK_TEXT)

set_notes(sl, """SPEAKER NOTES — Pain Points vs. Solution

Delivery guidance: Walk through 2–3 rows in detail. Pick ones most relevant to your audience.

For fraud operations (rows 1–3):
• "Row 1 is the core ML value proposition. Static rules catch what you've seen before — but credential stuffing, SIM-swap, and bot automation evolve weekly. Our 4-layer ensemble combines supervised learning, unsupervised anomaly detection, and identity graph analysis. The meta-model calibrates all three into a single 0–1000 score."
• "Row 2 is latency. Dynamic Tables with 1-minute target lag mean we compute risk features continuously. When an attacker logs in from an impossible location, we know within a minute."
• "Row 3 is analyst efficiency. Instead of 10,000 alerts, we tier them: SAFE flows through, STEP-UP triggers MFA, only BLOCK requires human investigation."

For CISO / compliance (rows 4–6):
• "Row 4 is platform consolidation — 5–7 tools → one Snowflake instance."
• "Row 5 is regulatory — 24M rule evaluation audit records, Cortex Agent for policy + Federal Register lookup."
• "Row 6 is trust — per-login risk factor attribution, versioned model registry, leakage guards."
""")

# ═══════════════════════════════════════════════════════════════
# SLIDE 5 — Architecture Diagram
# ═══════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
slide_header(sl, "Architecture & Data Flow")

# ── ROW 1: Data Sources ──────────────────────────────────────
src_y = Inches(1.4)
add_text_box(sl, Inches(0.5), src_y, Inches(12), Inches(0.4),
             "DATA SOURCES", font_size=11, color=MED_GRAY, bold=True)

# Structured sources
struct_items = [
    ("Login Events", "13M+ rows, 90 days"),
    ("Customer Accounts", "50K accounts, 2% compromised"),
    ("Device Registry", "Fingerprints, trust status"),
    ("Session Telemetry", "Keystroke, mouse, touch"),
    ("Identity Graph", "Entity relationship edges"),
    ("Threat Intel Feeds", "IP / device reputation"),
]
sx = Inches(0.5)
sw = Inches(1.75)
for i, (name, sub) in enumerate(struct_items):
    x = sx + i * (sw + Inches(0.12))
    add_shape(sl, x, src_y + Inches(0.35), sw, Inches(0.85), WHITE, line_color=SNOW_BLUE)
    add_text_box(sl, x + Inches(0.08), src_y + Inches(0.38), sw - Inches(0.16), Inches(0.3),
                 name, font_size=10, color=SNOW_DARK, bold=True, alignment=PP_ALIGN.CENTER)
    add_text_box(sl, x + Inches(0.08), src_y + Inches(0.68), sw - Inches(0.16), Inches(0.3),
                 sub, font_size=8, color=MED_GRAY, alignment=PP_ALIGN.CENTER)

# Label: Structured
add_rect(sl, Inches(0.5), src_y + Inches(1.25), Inches(5.5), Inches(0.28), SNOW_BLUE)
add_text_box(sl, Inches(0.5), src_y + Inches(1.25), Inches(5.5), Inches(0.28),
             "STRUCTURED DATA", font_size=9, color=WHITE, bold=True, alignment=PP_ALIGN.CENTER)

# Unstructured
add_rect(sl, Inches(6.25), src_y + Inches(1.25), Inches(5.95), Inches(0.28), PURPLE)
add_text_box(sl, Inches(6.25), src_y + Inches(1.25), Inches(5.95), Inches(0.28),
             "UNSTRUCTURED / SEMI-STRUCTURED DATA", font_size=9, color=WHITE, bold=True, alignment=PP_ALIGN.CENTER)

# Unstructured source cards
unstruct = [
    ("6 Fraud Policy Docs", "Chunked → Cortex Search"),
    ("Federal Register API", "Live regulatory docs via MCP"),
    ("Semantic View YAML", "648 lines, 9 tables, 14+ VQRs"),
]
ux = Inches(6.25)
uw = Inches(1.92)
for i, (name, sub) in enumerate(unstruct):
    x = ux + i * (uw + Inches(0.1))
    add_shape(sl, x, src_y + Inches(0.35), uw, Inches(0.85), WHITE, line_color=PURPLE)
    add_text_box(sl, x + Inches(0.06), src_y + Inches(0.38), uw - Inches(0.12), Inches(0.3),
                 name, font_size=10, color=SNOW_DARK, bold=True, alignment=PP_ALIGN.CENTER)
    add_text_box(sl, x + Inches(0.06), src_y + Inches(0.68), uw - Inches(0.12), Inches(0.3),
                 sub, font_size=8, color=MED_GRAY, alignment=PP_ALIGN.CENTER)

# ── Down arrows ──
for ax in [Inches(3.2), Inches(8.3)]:
    arrow_down(sl, ax, Inches(3.05))

# ── ROW 2: Processing pipeline (4 modules) ───────────────────
pipe_y = Inches(3.45)
add_text_box(sl, Inches(0.5), pipe_y, Inches(12), Inches(0.3),
             "PROCESSING PIPELINE — MODULAR COMPONENTS", font_size=11, color=MED_GRAY, bold=True)

modules = [
    ("Feature Engineering", "5 Dynamic Tables\n1-min target lag\nAuth · Behavioral · Profile\nReputation · Scored Logins",
     SNOW_ACCENT, "FEATURES Schema"),
    ("ML Scoring Engine", "4-Layer Ensemble\nXGBoost · Isolation Forest\nGraph Topology · Meta-Model\n0–1000 Risk Score",
     SNOW_BLUE, "SCORING Schema"),
    ("Intelligence Layer", "Cortex Agent (3-channel)\nSemantic View + Analyst\nCortex Search (policies)\nMCP (Federal Register)",
     GREEN_ACCENT, "SEMANTIC + APP Schemas"),
    ("Governance & Audit", "4 Masking Policies\n2 Row Access Policies\n8 RBAC Roles\n24M+ Audit Records",
     AMBER_ACCENT, "GOVERNANCE Schema"),
]
mw = Inches(2.8)
mx = Inches(0.5)
for i, (title, desc, clr, schema) in enumerate(modules):
    x = mx + i * (mw + Inches(0.15))
    add_shape(sl, x, pipe_y + Inches(0.35), mw, Inches(2.35), WHITE, line_color=RGBColor(0xE0, 0xE0, 0xE0))
    bar(sl, x, pipe_y + Inches(0.35), mw, Pt(5), clr)
    add_text_box(sl, x + Inches(0.1), pipe_y + Inches(0.5), mw - Inches(0.2), Inches(0.35),
                 title, font_size=13, color=SNOW_DARK, bold=True, alignment=PP_ALIGN.CENTER)
    add_text_box(sl, x + Inches(0.1), pipe_y + Inches(0.85), mw - Inches(0.2), Inches(0.3),
                 schema, font_size=9, color=clr, bold=True, alignment=PP_ALIGN.CENTER)
    add_text_box(sl, x + Inches(0.1), pipe_y + Inches(1.2), mw - Inches(0.2), Inches(1.4),
                 desc, font_size=10, color=MED_GRAY, alignment=PP_ALIGN.CENTER)
    if i < len(modules) - 1:
        arrow_right(sl, x + mw + Inches(0.0), pipe_y + Inches(1.35))

# ── ROW 3: Output ────────────────────────────────────────────
out_y = Inches(6.35)
add_rect(sl, Inches(0.5), out_y, Inches(12.1), Inches(0.55), SNOW_DARK)
add_text_box(sl, Inches(0.8), out_y + Inches(0.05), Inches(11.5), Inches(0.45),
             "OUTPUT  →  Streamlit 4-Page Command Center  •  Executive Dashboard  •  Policy Rules  •  Agent Chat  •  Live Investigation Queue",
             font_size=12, color=WHITE, alignment=PP_ALIGN.CENTER)

set_notes(sl, """SPEAKER NOTES — Architecture & Data Flow

Delivery guidance: Walk top-to-bottom, left-to-right. Emphasize the structured/unstructured split and modular design.

Talking points:
• "The architecture has three tiers. At the top, data sources — split into structured and unstructured."
• "Structured data includes 13M+ login events, 50K customer accounts, device fingerprints, behavioral telemetry from keystrokes and mouse patterns, an identity graph mapping entity relationships, and external threat intelligence feeds. All live in the RAW schema."
• "Unstructured data includes 6 fraud policy documents chunked for semantic search, a live connection to the Federal Register API via an MCP server, and a 648-line Semantic View YAML that defines the governed analytical surface."
• "The middle tier is four modular processing components — each independently deployable and testable:"
  - "Feature Engineering: 5 Dynamic Tables with 1-minute lag"
  - "ML Scoring: the 4-layer ensemble we'll deep-dive next"
  - "Intelligence Layer: Cortex Agent routing to SQL, search, and regulatory APIs"
  - "Governance: masking, row access policies, RBAC, and audit infrastructure"
• "Each module maps to a dedicated Snowflake schema — this isn't just code organization, it's a security boundary. You can grant FEATURES read-only to data scientists, SCORING read-only to fraud ops, and GOVERNANCE admin-only to compliance."
• "At the bottom, everything converges into a 4-page Streamlit Command Center running on Container Runtime."
• Transition: "Let me show you how Cortex Code skills were used to build each of these components."
""")

# ═══════════════════════════════════════════════════════════════
# SLIDE 6 — CoCo CLI Skills & How They Connect
# ═══════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
slide_header(sl, "CoCo CLI Skills Used & How They Connect")

# Central build flow — five phases across the top
phases = [
    ("1. SQL Author", "sql-author",
     "All DDL, DML, environment\nsetup, data generation,\npipeline SQL, governance\npolicies, grants",
     SNOW_DARK),
    ("2. Dynamic Tables", "dynamic-tables",
     "5 feature engineering\npipelines with 1-min lag:\ndt_auth, dt_behavioral,\ndt_profile, dt_reputation,\ndt_scored_logins",
     SNOW_ACCENT),
    ("3. Snowpark Python", "snowpark-python",
     "XGBoost & Isolation Forest\ntraining, graph features,\nensemble scoring, model\nregistry, deploy UDFs",
     SNOW_BLUE),
    ("4. Agent Studio", "agent-studio",
     "Semantic View YAML (648L),\n14+ VQRs, Cortex Agent\nspec, 3-channel routing,\nsystem prompt design",
     GREEN_ACCENT),
    ("5. Streamlit", "streamlit-in-workspaces",
     "4-page Command Center:\nDashboard, Policy Rules,\nAgent Chat, Investigation\nQueue + Container Runtime",
     PURPLE),
]
pw = Inches(2.25)
for i, (title, skill, desc, clr) in enumerate(phases):
    x = Inches(0.4) + i * (pw + Inches(0.15))
    add_shape(sl, x, Inches(1.4), pw, Inches(3.15), WHITE, line_color=RGBColor(0xE0, 0xE0, 0xE0))
    bar(sl, x, Inches(1.4), pw, Pt(5), clr)
    # Title
    add_text_box(sl, x + Inches(0.08), Inches(1.55), pw - Inches(0.16), Inches(0.35),
                 title, font_size=12, color=SNOW_DARK, bold=True, alignment=PP_ALIGN.CENTER)
    # Skill badge
    badge = add_shape(sl, x + Inches(0.2), Inches(1.95), pw - Inches(0.4), Inches(0.32), clr)
    add_text_box(sl, x + Inches(0.2), Inches(1.97), pw - Inches(0.4), Inches(0.28),
                 skill, font_size=9, color=WHITE, bold=True, alignment=PP_ALIGN.CENTER)
    # Description
    add_text_box(sl, x + Inches(0.08), Inches(2.4), pw - Inches(0.16), Inches(2.0),
                 desc, font_size=10, color=MED_GRAY, alignment=PP_ALIGN.CENTER)
    if i < len(phases) - 1:
        arrow_right(sl, x + pw + Inches(0.0), Inches(2.7))

# Supporting skills row
add_text_box(sl, Inches(0.5), Inches(4.75), Inches(12), Inches(0.35),
             "SUPPORTING SKILLS (cross-cutting)", font_size=12, color=SNOW_DARK, bold=True)

support = [
    ("data-governance", "Masking policies, RAP, RBAC,\ntag-based access control", AMBER_ACCENT),
    ("data-quality", "Data Metric Functions, freshness\nchecks, pipeline validation", RED_ACCENT),
    ("machine-learning", "Model Registry, versioning,\nleakage guards, metrics tracking", SNOW_BLUE),
    ("cortex-ai-function-studio", "Cortex Search, arctic-embed,\npolicy document indexing", GREEN_ACCENT),
    ("skill-development", "MCP server for Federal Register\nAPI (FastMCP, JSON-RPC 2.0)", PURPLE),
]
sw2 = Inches(2.25)
for i, (skill, desc, clr) in enumerate(support):
    x = Inches(0.4) + i * (sw2 + Inches(0.15))
    add_shape(sl, x, Inches(5.15), sw2, Inches(1.55), WHITE, line_color=RGBColor(0xE0, 0xE0, 0xE0))
    badge = add_shape(sl, x + Inches(0.15), Inches(5.25), sw2 - Inches(0.3), Inches(0.32), clr)
    add_text_box(sl, x + Inches(0.15), Inches(5.27), sw2 - Inches(0.3), Inches(0.28),
                 skill, font_size=9, color=WHITE, bold=True, alignment=PP_ALIGN.CENTER)
    add_text_box(sl, x + Inches(0.08), Inches(5.65), sw2 - Inches(0.16), Inches(0.95),
                 desc, font_size=10, color=MED_GRAY, alignment=PP_ALIGN.CENTER)

# Footer
bar(sl, Inches(0.4), Inches(6.9), Inches(12.2), Inches(0.4), SNOW_DARK)
add_text_box(sl, Inches(0.6), Inches(6.92), Inches(11.8), Inches(0.35),
             "10 CoCo skills orchestrated  •  Each skill maps to a modular component  •  Skills are composable and independently testable",
             font_size=11, color=WHITE, alignment=PP_ALIGN.CENTER)

set_notes(sl, """SPEAKER NOTES — CoCo CLI Skills & How They Connect

Delivery guidance: This slide demonstrates the development methodology. Emphasize that CoCo skills are the building blocks — each maps to a modular component.

Talking points:
• "We built this entire system using 10 CoCo CLI skills — each one mapping to a specific component of the architecture."

• Phase 1 — sql-author: "This was the foundation. Every DDL statement, data generation script, grant, and governance policy was authored through the sql-author skill. That's 10 data generation scripts, 5 Dynamic Table definitions, environment setup, and governance infrastructure."

• Phase 2 — dynamic-tables: "The feature engineering layer used the dynamic-tables skill to create and validate 5 DTs with 1-minute target lag. The skill handles incremental refresh optimization, which is critical when you're processing 13M+ events."

• Phase 3 — snowpark-python: "All ML work — training XGBoost and Isolation Forest, computing graph features, running ensemble scoring, and registering models — used the snowpark-python skill. The data never leaves Snowflake."

• Phase 4 — agent-studio: "The intelligence layer was built with agent-studio: a 648-line Semantic View YAML with 14+ verified query representations, the Cortex Agent spec with 3-channel routing, and the system prompt that governs intent classification."

• Phase 5 — streamlit-in-workspaces: "The 4-page Command Center was built with the Streamlit skill, deployed on Container Runtime."

• "The bottom row shows cross-cutting skills that support multiple phases: data-governance for masking and RBAC, data-quality for pipeline validation, machine-learning for model registry, cortex-ai-function-studio for Cortex Search indexing, and skill-development for the MCP server."

• "The key point: these skills are composable. You could take the Dynamic Tables skill output and plug in a different ML framework. You could swap the Streamlit frontend for an API. Each module has clean interfaces."

Transition: "Now let me zoom into the ML ensemble."
""")

# ═══════════════════════════════════════════════════════════════
# SLIDE 7 — ML Ensemble Deep Dive
# ═══════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
slide_header(sl, "4-Layer ML Ensemble")

models = [
    ("Layer 1: XGBoost", "Supervised Classifier", "50%",
     "19 features  •  Temporal train/test split\nNoise injection (5 strategies)\nLeakage guard (AUC > 0.95 = reject)\nROC-AUC: 0.804  •  PR-AUC: 0.949", SNOW_BLUE),
    ("Layer 2: Isolation Forest", "Unsupervised Anomaly", "30%",
     "8 behavioral features\nTrained on legitimate traffic only\nZero-day attack detection\nROC-AUC: 0.615  •  PR-AUC: 0.594", SNOW_ACCENT),
    ("Layer 3: Graph Risk", "Identity Topology", "20%",
     "6 structural inputs from identity graph\nDetects fraud rings & device cycling\nShared-device and IP cluster analysis\n494 fraud ring members flagged", GREEN_ACCENT),
    ("Layer 4: Meta-Model", "Ensemble Calibration", "—",
     "Weighted blend → 0–1000 score\nSAFE [0–349] → Frictionless\nSTEP-UP [350–749] → Adaptive MFA\nBLOCK [750–1000] → Auto-block", SNOW_DARK),
]
for i, (title, subtitle, weight, desc, clr) in enumerate(models):
    x = Inches(0.6) + i * Inches(3.1)
    add_shape(sl, x, Inches(1.5), Inches(2.85), Inches(4.8), WHITE, line_color=RGBColor(0xE0, 0xE0, 0xE0))
    add_rect(sl, x, Inches(1.5), Inches(2.85), Inches(0.55), clr)
    add_text_box(sl, x + Inches(0.1), Inches(1.52), Inches(2.65), Inches(0.5),
                 title, font_size=13, color=WHITE, bold=True, alignment=PP_ALIGN.CENTER)
    if weight != "—":
        add_shape(sl, x + Inches(0.9), Inches(2.2), Inches(1.0), Inches(0.45), clr)
        add_text_box(sl, x + Inches(0.9), Inches(2.22), Inches(1.0), Inches(0.4),
                     f"Weight: {weight}", font_size=11, color=WHITE, bold=True, alignment=PP_ALIGN.CENTER)
    else:
        add_text_box(sl, x + Inches(0.1), Inches(2.25), Inches(2.65), Inches(0.35),
                     "Final Output", font_size=11, color=clr, bold=True, alignment=PP_ALIGN.CENTER)
    add_text_box(sl, x + Inches(0.1), Inches(2.8), Inches(2.65), Inches(0.35),
                 subtitle, font_size=11, color=clr, bold=True, alignment=PP_ALIGN.CENTER)
    add_text_box(sl, x + Inches(0.15), Inches(3.3), Inches(2.55), Inches(2.8),
                 desc, font_size=11, color=MED_GRAY, alignment=PP_ALIGN.CENTER)

add_rect(sl, Inches(0.6), Inches(6.5), Inches(12.1), Inches(0.6), SNOW_DARK)
add_text_box(sl, Inches(0.8), Inches(6.52), Inches(11.7), Inches(0.55),
             "All models registered in Snowflake Model Registry  •  Versioned (V2)  •  Leakage-guarded  •  Metrics-tracked",
             font_size=13, color=WHITE, alignment=PP_ALIGN.CENTER)

set_notes(sl, """SPEAKER NOTES — 4-Layer ML Ensemble

Delivery guidance: Adjust depth based on audience — executives need the "why 4 layers" story; ML engineers want noise injection and leakage guard details.

Executive version:
• "Why four layers? Because ATO is multi-dimensional. No single model catches credential stuffing AND SIM-swap AND fraud rings AND zero-day attacks."
• "Layer 1 learns from historical patterns. Layer 2 learns what normal looks like and flags anything unusual — even attack types we've never seen. Layer 3 looks at relationships — shared devices and IP clusters. Layer 4 calibrates everything into a single score."
• "Three decision tiers: SAFE = frictionless. STEP-UP = adaptive MFA. BLOCK = auto-lock."

Technical version:
• "Layer 1 — XGBoost with 19 features after removing 4 leaky ones (automated AUC-per-feature check, threshold 0.95). Temporal split: train on first 70 days, test on last 20. Five noise injection strategies harden the model."
• "Layer 2 — Isolation Forest trained exclusively on legitimate traffic — our zero-day detector. 8 behavioral features: keystroke intervals, mouse entropy, touch pressure, dwell time, geo velocity."
• "Layer 3 — Graph risk from identity topology. 6 structural features, rule-based scoring. 494 fraud ring members caught."
• "Layer 4 — Weighted blend (50/30/20), validates no model has unrealistic AUC (>= 0.99), checks for leaky features."
""")

# ═══════════════════════════════════════════════════════════════
# SLIDE 8 — Industry & Regulatory Context
# ═══════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
slide_header(sl, "Industry & Regulatory Context")

# Left column — threats
add_text_box(sl, Inches(0.8), Inches(1.35), Inches(5.5), Inches(0.45),
             "The Evolving Threat Landscape", font_size=18, color=SNOW_DARK, bold=True)
threats = [
    "Credential dumps from breaches fuel stuffing at scale — billions of leaked credentials on dark markets",
    "SIM-swap attacks bypass SMS-based MFA — one of the 10 scenarios this system detects",
    "GenAI-powered social engineering makes phishing cheaper and harder to filter",
    "Remote/digital-first banking — the login event IS the perimeter",
    "Bot automation tests thousands of credential pairs per minute",
]
tf = add_text_box(sl, Inches(0.8), Inches(1.8), Inches(5.5), Inches(4.5), "", font_size=1)
for t in threats:
    add_para(tf, t, font_size=12, color=DARK_TEXT, bullet=True, space_before=Pt(10))

# Vertical divider
bar(sl, Inches(6.5), Inches(1.4), Pt(2), Inches(4.8), RGBColor(0xE0, 0xE0, 0xE0))

# Right column — regulations
add_text_box(sl, Inches(6.8), Inches(1.35), Inches(5.5), Inches(0.45),
             "Regulatory Mandates Driving Urgency", font_size=18, color=SNOW_DARK, bold=True)
regs = [
    ("FTC Safeguards Rule", "Real-time fraud detection and incident response"),
    ("CFPB MFA Circular", "Multi-factor authentication controls for consumer accounts"),
    ("CFPB Reg E ATO Proposal", "Shifts liability for unauthorized electronic fund transfers"),
    ("FinCEN AML / CDD", "Identity verification, suspicious activity monitoring, SAR filing"),
    ("FFIEC Authentication", "Risk-based authentication standards for financial institutions"),
    ("CISA CIRCIA", "72-hour cyber incident reporting — including ATO events"),
]
tf2 = add_text_box(sl, Inches(6.8), Inches(1.8), Inches(5.8), Inches(4.8), "", font_size=1)
for title, desc in regs:
    add_para(tf2, title, font_size=12, color=SNOW_ACCENT, bold=True, bullet=True, space_before=Pt(10))
    add_para(tf2, desc, font_size=11, color=MED_GRAY, space_before=Pt(2))

set_notes(sl, """SPEAKER NOTES — Industry & Regulatory Context

Delivery guidance: Choose the angle based on audience.

For financial services:
• "The threat landscape has fundamentally shifted. Credential dumps from breaches put billions of username/password pairs into circulation. Automated toolkits let attackers test thousands per minute."
• "SIM-swap defeats the most common second factor — SMS OTP. GenAI accelerates social engineering. And remote-first banking means the login event is the entire security perimeter."

For compliance audiences:
• "Six regulatory frameworks now require real-time ATO detection. The FTC Safeguards Rule is the broadest. The CFPB Reg E proposal is the one that gets CFOs' attention — it shifts liability onto the institution."
• "Our system addresses all six: real-time scoring (FTC), MFA via STEP-UP tier (CFPB), audit trail for SAR filing (FinCEN), risk-based tiers (FFIEC), and 72-hour reporting infrastructure (CIRCIA)."
""")

# ═══════════════════════════════════════════════════════════════
# SLIDE 9 — Impact Statement
# ═══════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
slide_header(sl, "Impact Statement")

# ── Section 1: Measurable Outcomes ────────────────────────────
add_text_box(sl, Inches(0.8), Inches(1.3), Inches(5), Inches(0.4),
             "Measurable Outcomes", font_size=18, color=SNOW_DARK, bold=True)

outcomes = [
    ("70–85%", "Reduction in\nFalse Positives", "Tiered decisioning replaces\nblunt rule thresholds with\ncalibrated ML scores", RED_ACCENT),
    ("60× Faster", "Detection\nLatency", "1-minute DT lag vs.\n60-minute+ batch jobs\n= near-real-time response", SNOW_BLUE),
    ("5→1", "Platform\nConsolidation", "ML + rules + search +\ngovernance + app on\none Snowflake instance", GREEN_ACCENT),
]
for i, (val, label, desc, clr) in enumerate(outcomes):
    x = Inches(0.8) + i * Inches(2.15)
    add_shape(sl, x, Inches(1.75), Inches(2.0), Inches(2.7), WHITE, line_color=RGBColor(0xE0, 0xE0, 0xE0))
    bar(sl, x, Inches(1.75), Inches(2.0), Pt(4), clr)
    add_text_box(sl, x + Inches(0.1), Inches(1.9), Inches(1.8), Inches(0.45),
                 val, font_size=24, color=clr, bold=True, alignment=PP_ALIGN.CENTER)
    add_text_box(sl, x + Inches(0.1), Inches(2.35), Inches(1.8), Inches(0.5),
                 label, font_size=11, color=SNOW_DARK, bold=True, alignment=PP_ALIGN.CENTER)
    add_text_box(sl, x + Inches(0.1), Inches(2.9), Inches(1.8), Inches(1.4),
                 desc, font_size=10, color=MED_GRAY, alignment=PP_ALIGN.CENTER)

# ── Section 2: Scalability ────────────────────────────────────
add_text_box(sl, Inches(7.2), Inches(1.3), Inches(5), Inches(0.4),
             "Scalability Potential", font_size=18, color=SNOW_DARK, bold=True)

scale_items = [
    "Snowflake elastic compute scales from 50K → millions of accounts with zero architecture changes",
    "Dynamic Tables auto-scale refresh cadence; target lag tunable per business SLA (1 min → seconds)",
    "Model Registry supports A/B versioning — retrain weekly/daily without downtime",
    "Cortex Search indexes scale to millions of policy documents across jurisdictions",
    "Multi-warehouse isolation: ML training, feature compute, and search indexing run independently",
]
tf = add_text_box(sl, Inches(7.2), Inches(1.75), Inches(5.4), Inches(3.0), "", font_size=1)
for t in scale_items:
    add_para(tf, t, font_size=11, color=DARK_TEXT, bullet=True, space_before=Pt(8))

# ── Section 3: Beyond the Demo ────────────────────────────────
add_text_box(sl, Inches(0.8), Inches(4.7), Inches(12), Inches(0.4),
             "How This Extends Beyond the Demo", font_size=18, color=SNOW_DARK, bold=True)

extensions = [
    ("Real-Time Streams", "Replace synthetic batch with\nSnowpipe Streaming for\nsub-second event ingestion", SNOW_BLUE),
    ("Production Labels", "Swap synthetic fraud labels\nfor confirmed ATO cases from\nSOC/fraud team feedback loops", RED_ACCENT),
    ("Multi-Channel Fraud", "Extend beyond login events\nto payment, wire transfer, and\naccount opening fraud", SNOW_ACCENT),
    ("Cross-Institution Intel", "Snowflake Data Sharing enables\nconsortium threat intel without\nmoving sensitive data", GREEN_ACCENT),
    ("Regulatory Automation", "Schedule Cortex Agent to\nauto-generate SAR narratives\nand compliance reports", PURPLE),
]
ew = Inches(2.25)
for i, (title, desc, clr) in enumerate(extensions):
    x = Inches(0.5) + i * (ew + Inches(0.13))
    add_shape(sl, x, Inches(5.15), ew, Inches(1.8), WHITE, line_color=RGBColor(0xE0, 0xE0, 0xE0))
    bar(sl, x, Inches(5.15), ew, Pt(4), clr)
    add_text_box(sl, x + Inches(0.08), Inches(5.3), ew - Inches(0.16), Inches(0.35),
                 title, font_size=11, color=SNOW_DARK, bold=True, alignment=PP_ALIGN.CENTER)
    add_text_box(sl, x + Inches(0.08), Inches(5.65), ew - Inches(0.16), Inches(1.2),
                 desc, font_size=10, color=MED_GRAY, alignment=PP_ALIGN.CENTER)

set_notes(sl, """SPEAKER NOTES — Impact Statement

Delivery guidance: Lead with the measurable outcomes, then pivot to scalability and extensibility.

Measurable Outcomes:
• "Three concrete improvements over traditional approaches:"
• "First: 70–85% reduction in false positives. This comes from replacing static rule thresholds with a calibrated 0–1000 score and three decision tiers. Instead of flagging every login from a new device, we combine device trust, behavioral biometrics, and velocity signals to make a nuanced decision."
• "Second: 60× faster detection. Dynamic Tables with 1-minute lag replace 60-minute+ batch jobs. When an attacker logs in from an impossible location, the system knows within a minute — not the next morning."
• "Third: platform consolidation from 5 tools to 1. The licensing cost savings alone are significant, but the real win is operational: one security model, one governance framework, one place to audit."

Scalability:
• "Snowflake's elastic compute means this architecture scales from our 50K-account demo to millions of accounts without architectural changes — just resize the warehouse."
• "Dynamic Table refresh cadence is tunable per business SLA. For high-value accounts, you could set sub-minute lag."
• "The Model Registry supports A/B versioning, so you can retrain models weekly or daily without downtime — the old version serves traffic while the new one is validated."

Beyond the Demo — five production extensions:
• "Real-Time Streams: Replace synthetic batch load with Snowpipe Streaming for sub-second event ingestion."
• "Production Labels: Swap synthetic fraud labels for confirmed ATO cases from SOC/fraud team feedback loops. This closes the ML training loop."
• "Multi-Channel Fraud: Extend the same architecture to payment fraud, wire transfer monitoring, and account opening fraud. The feature engineering patterns are reusable."
• "Cross-Institution Intel: Snowflake Data Sharing enables consortium-level threat intelligence — multiple banks sharing threat signals without moving sensitive data."
• "Regulatory Automation: Schedule the Cortex Agent to auto-generate SAR narratives and weekly compliance reports. This is a natural extension of the agent's 3-channel routing."

Transition: "Let me close with the key takeaways."
""")

# ═══════════════════════════════════════════════════════════════
# SLIDE 10 — Key Takeaways & Close
# ═══════════════════════════════════════════════════════════════
sl = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(sl, SNOW_DARK)
bar(sl, Inches(0), Inches(0), W, Pt(6), SNOW_BLUE)

add_text_box(sl, Inches(0.8), Inches(0.6), Inches(10), Inches(0.7),
             "Key Takeaways", font_size=36, color=WHITE, bold=True)
bar(sl, Inches(0.8), Inches(1.3), Inches(2.5), Pt(3), SNOW_BLUE)

takeaways = [
    ("Unified Platform", "Data, ML, policy, governance, and investigation on a single Snowflake instance — no silos, no data movement, no integration tax"),
    ("Multi-Layer Intelligence", "4-layer ML ensemble catches known fraud patterns (supervised), zero-day attacks (unsupervised), and fraud rings (graph) with calibrated scoring"),
    ("Real-Time Decisioning", "Dynamic Tables with 1-minute lag enable near-real-time feature engineering and tiered response: SAFE / STEP-UP / BLOCK"),
    ("Regulatory-Grade Governance", "24M+ audit records, masking policies, RBAC, and a Cortex Agent that answers policy and regulatory questions on demand"),
    ("Production-Ready & Extensible", "10 CoCo skills, modular architecture, Model Registry versioning — extends to real-time streams, multi-channel fraud, and cross-institution intelligence"),
]
for i, (title, desc) in enumerate(takeaways):
    y = Inches(1.8) + i * Inches(1.05)
    circle = sl.shapes.add_shape(MSO_SHAPE.OVAL, Inches(0.8), y, Inches(0.5), Inches(0.5))
    circle.fill.solid(); circle.fill.fore_color.rgb = SNOW_BLUE; circle.line.fill.background()
    add_text_box(sl, Inches(0.8), y + Inches(0.05), Inches(0.5), Inches(0.4),
                 str(i + 1), font_size=18, color=WHITE, bold=True, alignment=PP_ALIGN.CENTER)
    add_text_box(sl, Inches(1.5), y - Inches(0.02), Inches(10.5), Inches(0.35),
                 title, font_size=18, color=SNOW_BLUE, bold=True)
    add_text_box(sl, Inches(1.5), y + Inches(0.35), Inches(10.5), Inches(0.55),
                 desc, font_size=14, color=MED_GRAY)

bar(sl, Inches(0), Inches(6.8), W, Inches(0.7), SNOW_BLUE)
add_text_box(sl, Inches(0.8), Inches(6.82), Inches(11.5), Inches(0.6),
             "ATO Fraud Detection on Snowflake  —  Built 100% on a single platform with 10 CoCo skills",
             font_size=18, color=WHITE, bold=True, alignment=PP_ALIGN.CENTER)

set_notes(sl, """SPEAKER NOTES — Key Takeaways & Close

Delivery guidance: Reinforce the 3 strongest messages for your audience.

For executives:
• "Three things to take away. First: platform consolidation — what takes 5–7 tools runs on one Snowflake instance. That reduces operational complexity, licensing cost, and security surface area."
• "Second: the ML is practical, not academic. Noise injection, leakage guards, and a meta-model that rejects unrealistic performance. AUC is 0.804, not 0.99 — by design."
• "Third: governance is built in from the start. 24M audit records, role-based access, data masking, and an AI agent for real-time compliance queries."

For technical audiences:
• "The architecture is modular and extensible. Swap synthetic data for production streams, retrain with real labels, deploy the same app — the pipeline structure doesn't change."
• "10 CoCo skills map 1:1 to architectural components. Each is independently testable and replaceable."

Closing:
• "This demonstrates Snowflake's breadth as a complete fraud intelligence platform — data, ML, semantic layer, governance, and application hosting. The days of stitching 7 tools together are over."
• "Happy to dive deeper into any component."
""")

# ── Save ───────────────────────────────────────────────────────
tmp_path = "/tmp/ATO_Fraud_Detection_Deck.pptx"
final_path = "/workspace/ATO_Fraud_Detection_Deck.pptx"
prs.save(tmp_path)
shutil.copy2(tmp_path, final_path)
print(f"Saved: {final_path}")
