"""F-F13.2: writes ref/ircc_vocabulary.json, the IRCC offices, programs and organizations the validator reads.

    python scripts/ircc_vocabulary.py ref/ircc_vocabulary.json

Every row is typed in below from the IRCC and IRB pages it cites (read 2026-11-16), and the checks at the end refuse
the file before writing it: aliases lowercase and unique across rows after folding diacritics, the canonical name never
repeated as an alias, every former row replaced by a known row, an https source on every row, no em dash or semicolon
in the prose, and every one of the 17 visa codes covered by a current program row. To change a row, edit it here, run
the script, and commit both files. tests/test_ff13_2_sections_vocabulary.py checks that the script reproduces the
committed file byte for byte. Public facts only, no client data.
"""

import json, sys, unicodedata
OUT = sys.argv[1]
D = "2026-11-16"
B = "https://www.canada.ca/en/immigration-refugees-citizenship"
U_OFFICES = B + "/corporate/contact-ircc/offices.html"
U_VO = B + "/corporate/contact-ircc/offices/international-visa-offices.html"
U_VO_PARIS = B + "/corporate/contact-ircc/offices/international-visa-offices/paris.html"
U_APPT = B + "/corporate/contact-ircc/offices/canada-appointment-only.html"
U_CPC_E = B + "/corporate/contact-ircc/offices/case-processing-centre-edmonton-alberta.html"
U_CPC_M = B + "/corporate/contact-ircc/offices/case-processing-centre-mississauga-ontario.html"
U_CPC_O = B + "/corporate/contact-ircc/offices/case-processing-centre-ottawa-ontario.html"
U_CPC_S = B + "/corporate/contact-ircc/offices/case-processing-centre-sydney-nova-scotia.html"
U_VAC = B + "/corporate/contact-ircc/offices/find-visa-application-centre.html"
U_AUDIT16 = B + "/corporate/reports-statistics/audits/case-processing-centre-ottawa.html"
U_BIND2503 = B + "/corporate/transparency/transition-binders/minister-2025-03/departmental-overview.html"
U_BIND2505 = B + "/corporate/transparency/transition-binders/minister-2025-05/departmental-overview.html"
U_DM2022 = B + "/corporate/transparency/transition-binders/deputy-minister-2022/operations-sector.html"
U_DM26_TW = B + "/corporate/transparency/transition-binders/deputy-minister-2026/temporary-workers.html"
U_DM26_REF = B + "/corporate/transparency/transition-binders/deputy-minister-2026/refugee-resettlement-complementary-pathways.html"
U_DM26_FAM = B + "/corporate/transparency/transition-binders/deputy-minister-2026/family-reunification.html"
U_ARP26 = B + "/corporate/publications-manuals/annual-report-parliament-immigration-2026.html"
U_IMM5289 = B + "/services/application/application-forms-guides/guide-5289-sponsor-your-spouse-common-law-partner-conjugal-partner-dependent-child-complete-guide.html"
U_RESETTLE_OB = B + "/corporate/publications-manuals/operational-bulletins-manuals/refugee-protection/resettlement.html"
U_HOWSYS = B + "/services/refugees/about-refugee-system/how-system-works.html"
U_SDS = B + "/news/notices/end-student-direct-stream-nigeria-student-express.html"
U_PEI = B + "/corporate/mandate/policies-operational-instructions-agreements/agreements/federal-provincial-territorial/prince-edward-island/agreement-canada-prince-edward-island-atlantic-immigration-program.html"
U_EXPLORE = "https://ircc.canada.ca/explore-programs/"
U_IRB = "https://irb-cisr.gc.ca/en/board/pages/index.aspx"
U_GN_VEG = "https://globalnews.ca/news/3030312/vegreville-case-processing-centre-relocated-280-jobs-impacted-town"
U_CARE_CHILD = B + "/services/immigrate-canada/caregivers/children.html"
U_CARE_HMN = B + "/services/immigrate-canada/caregivers/people-high-medical-needs.html"
U_HCWIP = B + "/services/immigrate-canada/caregivers/home-care-worker-immigration-pilots/child-care-home-support/eligibility.html"
U_RCIP = B + "/services/immigrate-canada/rural-franco-pilots/rural-immigration/eligibility.html"
U_IRPR_87_4 = "https://laws-lois.justice.gc.ca/eng/regulations/SOR-2002-227/section-87.4.html"
U_FCIP = B + "/services/immigrate-canada/rural-franco-pilots/franco-immigration/eligibility.html"
U_SUV_END = B + "/news/notices/immigration-measures-entrepreneurs.html"
U_TRV_WITH_PERMIT = "https://ircc.canada.ca/english/helpcentre/answer.asp?qnum=1040&top=23"
U_SUPER_MI = B + "/corporate/mandate/policies-operational-instructions-agreements/ministerial-instructions/other-goals/super-visa-2026.html"
U_SUPER_APPLY = B + "/services/visit-canada/parent-grandparent-super-visa/apply.html"
READ = "Read 2026-11-16."

rows = []


def add(**r):
    base = dict(kind=None, canonical_name=None, ircc_aliases=[], common_variants=[], status="current",
                replaced_by=None, successor_note=None, organization="IRCC", letter_addressee="n/a", visa_codes=[], note=None,
                source_urls=[], source_note=READ, last_verified=D)
    base.update(r)
    c = fold(base["canonical_name"])
    base["ircc_aliases"] = [a for a in base["ircc_aliases"] if fold(a) != c]
    base["common_variants"] = [a for a in base["common_variants"] if fold(a) != c]
    rows.append(base)


def fold(s):
    s = unicodedata.normalize("NFKD", s)
    return "".join(c for c in s if not unicodedata.combining(c)).lower()


# ---------- processing centres in Canada ----------
pc_note = "Find an IRCC office, page modified 2026-08-14, read 2026-11-16."
add(id="office-cpc-edmonton", kind="office", canonical_name="Case Processing Centre in Edmonton",
    ircc_aliases=["cpc edmonton", "case processing centre (cpc): edmonton, alberta", "case processing centre in edmonton"],
    common_variants=["cpc-e", "edmonton case processing centre", "case processing centre edmonton"],
    letter_addressee="yes",
    note="Processes work permits, study permits, temporary resident extensions and TRPs, live-in caregiver and caring pathway PR, and RPRF loans.",
    source_urls=[U_OFFICES, U_CPC_E], source_note=pc_note + " CPC Edmonton page modified 2026-09-01.")
add(id="office-cpc-mississauga", kind="office", canonical_name="Case Processing Centre in Mississauga",
    ircc_aliases=["cpc mississauga", "case processing centre in mississauga", "cpc-m"],
    common_variants=["mississauga case processing centre", "case processing centre mississauga"],
    letter_addressee="yes",
    note="Processes family sponsorship, PR for protected persons and Convention refugees in Canada, and the TRP holder class. It handles digitized files only, paper goes to the IRCC Digitization Centre.",
    source_urls=[U_OFFICES, U_CPC_M], source_note=pc_note)
add(id="office-cpc-ottawa", kind="office", canonical_name="Case Processing Centre in Ottawa",
    ircc_aliases=["cpc ottawa", "case processing centre: ottawa, ontario", "cpc-o", "ottawa case processing centre"],
    common_variants=["case processing centre ottawa"],
    letter_addressee="yes",
    note="Processes in-Canada TRV applications from study or work permit holders, and PR visa applications from the United States and Canada after CPC Mississauga or CIO Sydney checks completeness.",
    source_urls=[U_OFFICES, U_CPC_O, U_AUDIT16],
    source_note=pc_note + " CPC Ottawa page modified 2023-12-08. The 2016 internal audit calls it the largest visa office in the IRCC network.")
add(id="office-cpc-sydney", kind="office", canonical_name="Case Processing Centre in Sydney",
    ircc_aliases=["cpc sydney", "cpc-sydney", "case processing centre: sydney, nova scotia"],
    common_variants=["sydney case processing centre", "case processing centre sydney", "cpc-s"],
    letter_addressee="yes",
    note="Sydney, Nova Scotia. Processes PR cards, citizenship and family sponsorship. Not the visa office in Sydney, Australia.",
    source_urls=[U_OFFICES, U_CPC_S], source_note=pc_note + " CPC Sydney page modified 2024-12-06.")
add(id="office-cio-sydney", kind="office", canonical_name="Centralized Intake Office in Sydney",
    ircc_aliases=["centralized intake office", "cio sydney", "cio"],
    common_variants=["cio-s", "centralised intake office", "centralized intake office sydney"],
    letter_addressee="yes",
    note="Sydney, Nova Scotia. Receives FSW, FST, CEC, PNP, Start-up Visa, Quebec economic and self-employed PR applications.",
    source_urls=[U_OFFICES], source_note=pc_note)
add(id="office-osc-ottawa", kind="office", canonical_name="Operations Support Centre in Ottawa",
    ircc_aliases=["operations support centre", "osc", "osc ottawa"],
    common_variants=["operational support centre", "operations support centre ottawa"],
    letter_addressee="yes",
    note="Processes IEC work permits, online in-Canada temporary resident applications, verification of status, and replacement and amendment of documents. A 2025 binder places the OSC in Gatineau.",
    source_urls=[U_OFFICES, U_BIND2503, U_AUDIT16], source_note=pc_note + " The 2016 audit writes operational support centre.")
add(id="office-ircc-digitization-centre", kind="office", canonical_name="IRCC Digitization Centre",
    ircc_aliases=["ircc digitization centre"], common_variants=["digitization centre", "digitisation centre"],
    letter_addressee="no",
    note="New Waterford and Sydney, Nova Scotia. A mail and courier address that digitizes paper for CPC Mississauga and CPC Sydney. It decides nothing, so a letter names the processing office.",
    source_urls=[U_CPC_M, U_CPC_S])
add(id="office-roc-ottawa", kind="office", canonical_name="Resettlement Operations Centre in Ottawa",
    ircc_aliases=["resettlement operations centre"], common_variants=["roc-o", "resettlement operations centre ottawa"],
    letter_addressee="on_request",
    note="Named in the 2025 minister binder. Its role in private sponsorship intake was not read on an applicant page.",
    source_urls=[U_BIND2503], source_note="Binder dated 2025-07-11, read 2026-11-16.")
add(id="office-goc-manila", kind="office", canonical_name="Manila Global Operations Centre",
    ircc_aliases=["manila global operations centre"], common_variants=["goc manila", "global operations centre manila", "global operations centre in manila"],
    letter_addressee="no",
    note="Internal processing hub. IRCC points applicants to the visa office list, so a letter names the visa office, not the hub.",
    source_urls=[U_BIND2505], source_note="Binder dated 2025-09-11, read 2026-11-16.")
add(id="office-goc-bucharest", kind="office", canonical_name="Bucharest Global Operations Centre",
    ircc_aliases=["bucharest global operations centre"], common_variants=["goc bucharest", "global operations centre bucharest", "global operations centre in bucharest"],
    letter_addressee="no", note="Internal processing hub, see the Manila row.",
    source_urls=[U_BIND2505], source_note="Binder dated 2025-09-11, read 2026-11-16.")
add(id="office-cpc-vegreville", kind="office", canonical_name="Case Processing Centre in Vegreville",
    ircc_aliases=["case processing centre in vegreville"], common_variants=["cpc vegreville", "cpc-v", "vegreville case processing centre"],
    status="former", replaced_by="office-cpc-edmonton", letter_addressee="no",
    note="Listed as a CPC in the 2016 IRCC audit. Relocated to Edmonton (announced 2016, move planned for 2018). The relocation is sourced from news, not from an IRCC page.",
    source_urls=[U_AUDIT16, U_GN_VEG], source_note="Audit dated 2016-10-13. Global News 2016-10-28 is a secondary source. Read 2026-11-16.")
add(id="office-vac", kind="office", canonical_name="Visa application centre",
    ircc_aliases=["visa application centre", "vac"], common_variants=["visa application center"],
    organization="private", letter_addressee="no",
    note="Private contractors for biometrics and passports. IRCC states they play no role in decisions, so a submission is never addressed to one.",
    source_urls=[U_VAC, U_OFFICES])

# ---------- visa offices outside Canada ----------
vo = [("Abu Dhabi", "United Arab Emirates"), ("Accra", "Ghana"), ("Amman", "Jordan"), ("Ankara", "Türkiye"),
      ("Bangkok", "Thailand"), ("Beijing", "China"), ("Beirut", "Lebanon"), ("Bogota", "Colombia"),
      ("Bucharest", "Romania"), ("Buenos Aires", "Argentina"), ("Cairo", "Egypt"), ("Colombo", "Sri Lanka"),
      ("Dakar", "Senegal"), ("Dar es Salaam", "Tanzania"), ("Guangzhou", "China"), ("Ho Chi Minh City", "Vietnam"),
      ("Hong Kong", "Hong Kong (SAR)"), ("Islamabad", "Pakistan"), ("Jakarta", "Indonesia"), ("Kingston", "Jamaica"),
      ("Lima", "Peru"), ("London", "United Kingdom"), ("Los Angeles", "United States"), ("Manila", "Philippines"),
      ("Mexico City", "Mexico"), ("Nairobi", "Kenya"), ("New Delhi", "India"), ("New York", "United States"),
      ("Paris", "France"), ("Port of Spain", "Trinidad and Tobago"), ("Port-au-Prince", "Haiti"),
      ("Pretoria", "South Africa"), ("Rabat", "Morocco"), ("Riyadh", "Saudi Arabia"), ("Rome", "Italy"),
      ("Sao Paulo", "Brazil"), ("Shanghai", "China"), ("Singapore", "Singapore"), ("Sydney", "Australia"),
      ("Tel Aviv", "Israel"), ("Tunis", "Tunisia"), ("Vienna", "Austria"), ("Warsaw", "Poland")]
spell = {"Bogota": ["Bogotá"], "Sao Paulo": ["São Paulo"], "Port of Spain": ["Port-of-Spain"],
         "Ho Chi Minh City": ["Ho Chi Minh"], "Port-au-Prince": ["Port au Prince"]}
# A bare city alias is left out where the city also names an IRCC office in Canada.
domestic_clash = {"London", "Sydney"}
city_note = {
    "Sydney": "Sydney, Australia. Always write the country, since CPC Sydney and CIO Sydney are in Nova Scotia.",
    "London": "London, United Kingdom. Always write the country, since IRCC has an appointment office in London, Ontario.",
    "Bangkok": "For Bhutan and Nepal, Bangkok handles temporary residents and Singapore permanent residents.",
    "Singapore": "For Bhutan and Nepal, Bangkok handles temporary residents and Singapore permanent residents.",
    "Nairobi": "For Nigeria, Nairobi handles temporary residents and Accra permanent residents.",
    "Accra": "For Nigeria, Nairobi handles temporary residents and Accra permanent residents.",
    "Manila": "Also serves Japan, the Republic of Korea and Taiwan.",
    "Vienna": "Also serves Germany.",
    "Warsaw": "Also serves Russia, Ukraine and Central Asia.",
    "Ankara": "IRCC writes Türkiye. Turkey is accepted as a variant.",
}
vo_note = ("Visa offices outside Canada, page modified 2026-07-17, read live 2026-11-16 (43 distinct offices across 261 rows). "
           "The canonical form follows the IRCC page title Visa office in Paris, France.")
for city, country in vo:
    slug = fold(city).replace(" ", "-")
    lc, lco = city.lower(), country.lower()
    ali = []
    var = []
    for n in [lc] + [s.lower() for s in spell.get(city, [])]:
        if city in domestic_clash:
            var += [f"canadian visa office in {n}, {lco}"]
        else:
            ali += [f"visa office in {n}"] if n == lc else []
            var += ([f"visa office in {n}"] if n != lc else []) + [f"{n} visa office", f"canadian visa office in {n}", f"visa section in {n}"]
    if city == "Ankara":
        var += ["visa office in ankara, turkey"]
    add(id=f"office-vo-{slug}", kind="office", canonical_name=f"Visa office in {city}, {country}",
        ircc_aliases=ali, common_variants=var, letter_addressee="yes", note=city_note.get(city),
        source_urls=[U_VO, U_VO_PARIS], source_note=vo_note)

former_vo = [("Washington", "United States"), ("Miami", "United States"), ("Brussels", "Belgium"), ("Berlin", "Germany"),
             ("Geneva", "Switzerland"), ("Kyiv", "Ukraine"), ("Moscow", "Russia"), ("Algiers", "Algeria"),
             ("Chandigarh", "India"), ("Bangalore", "India"), ("Seoul", "Republic of Korea"), ("Tokyo", "Japan"),
             ("Canberra", "Australia"), ("Abuja", "Nigeria"), ("Lagos", "Nigeria"), ("Addis Ababa", "Ethiopia")]
repl = {"Washington": "office-vo-new-york", "Miami": "office-vo-new-york", "Brussels": "office-vo-paris",
        "Berlin": "office-vo-vienna", "Geneva": "office-vo-paris", "Kyiv": "office-vo-warsaw", "Moscow": "office-vo-warsaw",
        "Algiers": "office-vo-paris", "Chandigarh": "office-vo-new-delhi", "Bangalore": "office-vo-new-delhi",
        "Seoul": "office-vo-manila", "Tokyo": "office-vo-manila", "Canberra": "office-vo-sydney",
        "Abuja": "office-vo-nairobi", "Lagos": "office-vo-nairobi", "Addis Ababa": "office-vo-nairobi"}
# Where the 2026 list names two offices for the country, the flag names both and replaced_by holds the first.
both = {"United States": "Visa office in Los Angeles or New York, United States (the 2026 list names both)",
        "Nigeria": "Visa office in Nairobi, Kenya (temporary residents) or Accra, Ghana (permanent residents)"}
for city, country in former_vo:
    slug = fold(city).replace(" ", "-")
    lc = city.lower()
    var = [f"{lc} visa office", f"canadian visa office in {lc}", f"visa section in {lc}"]
    if city == "Bangalore":
        var += ["visa office in bengaluru", "bengaluru visa office"]
    if city == "Kyiv":
        var += ["visa office in kiev", "kiev visa office"]
    add(id=f"office-vo-{slug}", kind="office", canonical_name=f"Visa office in {city}, {country}",
        ircc_aliases=[f"visa office in {lc}"], common_variants=var, status="former",
        replaced_by=repl[city], successor_note=both.get(country), letter_addressee="no",
        note=(f"Listed as an overseas office in the 2022 deputy minister binder and absent from the 2026 visa office list. "
              f"The mission may still exist, but IRCC no longer lists it as a processing visa office. "
              + (f"The 2026 list names more than one office for {country}, so the flag names them and replaced_by holds the first."
                 if country in both else f"replaced_by is the office the 2026 list names for {country}.")),
        source_urls=[U_DM2022, U_VO], source_note="Binder dated 2022-11-14. Visa office list read live 2026-11-16.")

# ---------- IRCC offices in Canada, by appointment only ----------
appt = [("calgary", "Calgary", "Alberta"), ("edmonton", "Edmonton", "Alberta"),
        ("vancouver-immigration", "Vancouver (Immigration office)", "British Columbia"),
        ("vancouver-citizenship", "Vancouver (Citizenship office)", "British Columbia"),
        ("surrey-citizenship", "Surrey (Citizenship office)", "British Columbia"),
        ("winnipeg", "Winnipeg", "Manitoba"), ("fredericton", "Fredericton", "New Brunswick"),
        ("st-johns", "St. John's", "Newfoundland and Labrador"), ("yellowknife", "Yellowknife", "Northwest Territories"),
        ("halifax", "Halifax", "Nova Scotia"), ("hamilton", "Hamilton", "Ontario"), ("kitchener", "Kitchener", "Ontario"),
        ("london-ontario", "London", "Ontario"), ("niagara-falls", "Niagara Falls", "Ontario"),
        ("ottawa", "Ottawa", "Ontario"), ("mississauga-citizenship", "Mississauga (Citizenship office)", "Ontario"),
        ("toronto-scarborough", "Toronto (Scarborough)", "Ontario"), ("toronto-etobicoke", "Toronto (Etobicoke)", "Ontario"),
        ("windsor", "Windsor", "Ontario"), ("charlottetown", "Charlottetown", "Prince Edward Island"),
        ("montreal", "Montréal", "Quebec"), ("saskatoon", "Saskatoon", "Saskatchewan"), ("whitehorse", "Whitehorse", "Yukon")]
for slug, label, prov in appt:
    base = label.split(" (")[0]
    lo = base.lower()
    note = "By appointment only. A letter is addressed here only when this office asked for the documents."
    if slug == "london-ontario":
        canon = "IRCC office in London, Ontario"
        ali = []
        var = ["london, ontario ircc office"]
        note = "By appointment only. Always write the province, since the visa office in London, United Kingdom is a different office."
    else:
        canon = f"IRCC office in {label}, {prov}"
        ali = [f"ircc office in {label.lower()}"]
        var = []
        if "(" not in label:
            var += [f"{lo} ircc office"]
        if slug in ("toronto-scarborough", "toronto-etobicoke", "surrey-citizenship"):
            ali += [f"ircc office in {slug.split('-')[1] if slug.startswith('toronto') else 'surrey'}"]
        if slug == "montreal":
            var += ["ircc office in montreal", "montreal ircc office"]
        if slug == "vancouver-immigration":
            var += ["vancouver immigration office"]
        if slug in ("ottawa", "edmonton"):
            note = "By appointment only. Not the Case Processing Centre in the same city."
    add(id=f"office-domestic-{slug}", kind="office", canonical_name=canon,
        ircc_aliases=ali, common_variants=var, letter_addressee="on_request", note=note,
        source_urls=[U_APPT], source_note="IRCC offices in Canada: By appointment only, page modified 2025-03-04, read 2026-11-16.")

# ---------- organizations and IRB divisions ----------
add(id="org-ircc", kind="organization", canonical_name="Immigration, Refugees and Citizenship Canada",
    ircc_aliases=["ircc"], common_variants=["immigration refugees and citizenship canada"],
    letter_addressee="yes", source_urls=[U_OFFICES])
add(id="org-cic", kind="organization", canonical_name="Citizenship and Immigration Canada",
    common_variants=["cic"], status="former", replaced_by="org-ircc", letter_addressee="no",
    note=("The department's former applied title. The Minister of Citizenship and Immigration and federal-provincial agreements "
          "(the 2022 PEI AIP agreement) still use the old wording, so a hit is a soft flag, never a hard fail. "
          "CIC also appears in IRCC web addresses (cic.gc.ca), so it matches as a whole word outside URLs only."),
    source_urls=[U_PEI], source_note="Agreement dated 2022-02-01, read 2026-11-16. The date of the rename was not read on an IRCC page.")
add(id="org-irb", kind="organization", canonical_name="Immigration and Refugee Board of Canada",
    ircc_aliases=["immigration and refugee board", "irb"], organization="IRB", letter_addressee="yes",
    source_urls=[U_IRB], source_note="IRB About the Board, read 2026-11-16.")
for slug, name, ab, codes, note in [
        ("rpd", "Refugee Protection Division", "rpd", ["REF-CLAIM"], "Hears and decides claims for refugee protection made in Canada. The addressee for REF-CLAIM documents."),
        ("rad", "Refugee Appeal Division", "rad", ["REF-CLAIM"], "Decides appeals from RPD decisions. An appeal is not a document type here yet."),
        ("id", "Immigration Division", None, [], "Admissibility hearings and detention reviews, outside the 17 codes. ID is left out as an alias, since it collides with ordinary text."),
        ("iad", "Immigration Appeal Division", "iad", ["FAM-SPOUSE", "FAM-PGP", "FAM-OTHER"], "Hears family class sponsorship appeals, removal order appeals and residency obligation appeals.")]:
    add(id=f"office-irb-{slug}", kind="office", canonical_name=name, ircc_aliases=[ab] if ab else [], organization="IRB",
        letter_addressee="yes", visa_codes=codes, note=note, source_urls=[U_IRB], source_note="IRB About the Board, read 2026-11-16.")
add(id="org-cbsa", kind="organization", canonical_name="Canada Border Services Agency",
    ircc_aliases=["cbsa"], organization="CBSA", letter_addressee="no",
    note="Port of entry and inland refugee claims, detention and removals. Not the addressee of an IRCC submission.",
    source_urls=[U_IRB])
add(id="org-esdc", kind="organization", canonical_name="Employment and Social Development Canada",
    ircc_aliases=["esdc"], organization="ESDC", letter_addressee="no",
    note="Decides LMIA applications. IRCC decides the work permit.", source_urls=[U_DM26_TW],
    source_note="Binder dated 2026-07-27, read 2026-11-16.")


# ---------- programs ----------
def P(**k):
    add(kind="program", **k)


P(id="prog-visitor-visa", canonical_name="Visitor visa (temporary resident visa)",
  ircc_aliases=["visitor visa", "temporary resident visa", "trv"], common_variants=["tourist visa", "visit visa"],
  visa_codes=["TR-VISIT", "TR-SUPER", "TR-STUDY", "TR-WP-EMP", "TR-WP-OPEN"],
  source_urls=[B + "/services/visit-canada.html", U_CPC_O, U_TRV_WITH_PERMIT, U_SUPER_MI],
  note=("IRCC issues a visitor visa or an eTA automatically with an initial study or work permit applied for before travel, "
        "so a study or work permit letter may name it. A PGWP is applied for in Canada, and a visa then needs its own application. "
        "A super visa is a multiple entry temporary resident visa, so a super visa letter may name it too."),
  source_note=("Read 2026-11-16 (cached copy dated 2026-11-05). TRV is the form on the CPC Ottawa page. "
               "Help Centre answer 1040, modified 2026-11-03, read 2026-11-16. Ministerial Instructions regarding the "
               "Parent and Grandparent Super Visa (2026), in force 2026-03-31, define the Super Visa as a multiple entry "
               "temporary resident visa, read 2026-11-19 (TR-SUPER added after the false flag on F-F14 case ff14-010)."))
P(id="prog-eta", canonical_name="Electronic travel authorization (eTA)",
  ircc_aliases=["electronic travel authorization", "eta"], common_variants=["electronic travel authorisation"],
  visa_codes=["TR-VISIT", "TR-STUDY", "TR-WP-EMP", "TR-WP-OPEN"],
  source_urls=[B + "/services/visit-canada.html", U_TRV_WITH_PERMIT, U_SUPER_APPLY],
  note=("Issued automatically with an initial study or work permit applied for before travel, see the visitor visa row. "
        "Not a program of TR-SUPER: a visa-exempt super visa applicant is directed to apply for an eTA, if one is needed, "
        "only after the super visa is approved, then gets a letter (super visa How to apply page, read 2026-11-19), so a "
        "letter that presents the eTA as the application is flagged."),
  source_note="Read 2026-11-16. Help Centre answer 1040, modified 2026-11-03.")
P(id="prog-business-visitor", canonical_name="Business visitor", ircc_aliases=["business visitor", "business visitors"],
  visa_codes=["TR-VISIT"], note="Work without a work permit, listed in the 2026 binder.", source_urls=[U_DM26_TW])
P(id="prog-super-visa", canonical_name="Parent and grandparent super visa",
  ircc_aliases=["super visa", "super visa for parents and grandparents"], common_variants=["supervisa"],
  visa_codes=["TR-SUPER"], source_urls=[B + "/services/visit-canada/parent-grandparent-super-visa.html"],
  source_note="Page title Super visa for parents and grandparents, read 2026-11-16 (cached copy dated 2026-11-11).")
P(id="prog-study-permit", canonical_name="Study permit",
  common_variants=["student visa", "student permit"], visa_codes=["TR-STUDY"],
  note="Student visa is common usage, but IRCC issues a study permit, so a letter that says student visa may be soft flagged.",
  source_urls=[B + "/services/study-canada/study-permit.html"])
P(id="prog-international-student-program", canonical_name="International Student Program",
  common_variants=["isp"], visa_codes=["TR-STUDY", "TR-PGWP"],
  source_urls=[B + "/corporate/transparency/committees/cimm-apr-20-2026/oag-report.html"], source_note="CIMM briefing dated 2026-08-18, read 2026-11-16.")
P(id="prog-sds", canonical_name="Student Direct Stream", status="former",
  replaced_by="prog-study-permit", visa_codes=["TR-STUDY"],
  note=("Ended 2024-11-08 at 2 p.m. ET. Later applications are regular study permits. SDS is left out as an alias, "
        "since a former name matches anywhere and SDS also means a safety data sheet."),
  source_urls=[U_SDS], source_note="Notice dated 2024-11-08, read 2026-11-16.")
P(id="prog-nse", canonical_name="Nigeria Student Express", status="former",
  replaced_by="prog-study-permit", visa_codes=["TR-STUDY"],
  note=("Ended 2024-11-08 with the SDS. NSE is left out as an alias, since a former name matches anywhere and NSE is also "
        "the National Stock Exchange of India, a common employer in a work history."),
  source_urls=[U_SDS], source_note="Notice dated 2024-11-08, read 2026-11-16.")
P(id="prog-fmcsp", canonical_name="Francophone Minority Communities Student Pilot",
  ircc_aliases=["francophone minority community student pilot", "francophone minority student pilot", "fmcsp", "fmscp"],
  visa_codes=["TR-STUDY"], note="IRCC spells it several ways on one page, abbreviations included. The canonical form is the one in the finalized logic model line.",
  source_urls=[B + "/corporate/transparency/committees/cimm-apr-20-2026/overview-management-response-action-plan.html"],
  source_note="Dated 2026-08-18, read 2026-11-16.")
P(id="prog-employer-specific-wp", canonical_name="Employer-specific work permit",
  ircc_aliases=["employer-specific work permits", "closed work permit"],
  common_variants=["lmia-based work permit", "lmia-exempt work permit", "employer specific work permit"],
  visa_codes=["TR-WP-EMP"], source_urls=[B + "/services/work-canada/employer-specific.html", U_DM26_TW],
  source_note="Read 2026-11-16. Closed appears in the 2026 binder in brackets.")
P(id="prog-open-wp", canonical_name="Open work permit",
  ircc_aliases=["open work permits"], common_variants=["owp", "spousal open work permit", "sowp", "bridging open work permit", "bowp"],
  visa_codes=["TR-WP-OPEN", "TR-PGWP"], source_urls=[B + "/services/work-canada/open-work-permit.html"],
  note="The page lists post-graduation work permit applicants among those who may get an open work permit.",
  source_note="Read 2026-11-16 (cached copy dated 2026-11-09), page modified 2026-03-31.")
P(id="prog-pgwp", canonical_name="Post-graduation work permit (PGWP)",
  ircc_aliases=["post-graduation work permit", "post-graduation work permits", "pgwp"],
  common_variants=["post graduation work permit", "post-graduation work permit program", "pgwpp"],
  visa_codes=["TR-PGWP"], note="The IRCC pages read call it a work permit, not a program, and the 2026 binder lists PGWPs under the International Mobility Program.",
  source_urls=[B + "/services/study-canada/work/after-graduation.html", U_DM26_TW], source_note="PGWP page modified 2026-03-09, read 2026-11-16.")
P(id="prog-tfwp", canonical_name="Temporary Foreign Worker Program",
  ircc_aliases=["tfwp"], visa_codes=["TR-WP-EMP"], note="Co-managed with ESDC. Every TFWP permit is employer-specific and needs an LMIA.",
  source_urls=[U_DM26_TW, U_ARP26])
P(id="prog-imp", canonical_name="International Mobility Program",
  ircc_aliases=["imp"], visa_codes=["TR-WP-EMP", "TR-WP-OPEN", "TR-PGWP"],
  note="LMIA-exempt work permits, PGWPs and spousal open work permits included.", source_urls=[U_DM26_TW, U_ARP26])
P(id="prog-imp-plus", canonical_name="International Mobility Program Plus", ircc_aliases=["imp+"],
  visa_codes=["TR-WP-OPEN"], note="Open work permit for Quebec Selection Certificate holders outside Quebec.",
  source_urls=[U_EXPLORE])
P(id="prog-global-talent-stream", canonical_name="Global Talent Stream", ircc_aliases=["gts"], visa_codes=["TR-WP-EMP"],
  note="A TFWP stream.", source_urls=[U_DM26_TW])
P(id="prog-sawp", canonical_name="Seasonal Agricultural Worker Program", ircc_aliases=["sawp"], visa_codes=["TR-WP-EMP"],
  note="A TFWP stream.", source_urls=[U_DM26_TW])
P(id="prog-global-skills-strategy", canonical_name="Global Skills Strategy", visa_codes=["TR-WP-EMP"],
  source_urls=[B + "/services/work-canada/employer-specific.html"])
P(id="prog-iec", canonical_name="International Experience Canada", ircc_aliases=["iec"],
  visa_codes=["TR-WP-EMP", "TR-WP-OPEN"], source_urls=[B + "/services/work-canada/employer-specific.html", U_OFFICES])
P(id="prog-lmia", canonical_name="Labour Market Impact Assessment (LMIA)", ircc_aliases=["labour market impact assessment", "lmia"],
  common_variants=["labor market impact assessment"], visa_codes=["TR-WP-EMP"], organization="ESDC",
  note="A document, not a program. Listed so a letter that names it is not flagged.", source_urls=[U_ARP26, U_DM26_TW])
P(id="prog-express-entry", canonical_name="Express Entry",
  visa_codes=["PR-EE-CEC", "PR-EE-FSW", "PR-EE-FST", "PR-PNP-EE"],
  note="The application system for the three federal programs and part of the PNP. EE is left out, since it is too short to match alone.",
  source_urls=[B + "/services/immigrate-canada/express-entry/who-can-apply/canadian-experience-class.html"])
P(id="prog-cec", canonical_name="Canadian Experience Class", ircc_aliases=["cec"], visa_codes=["PR-EE-CEC"],
  source_urls=[B + "/services/immigrate-canada/express-entry/who-can-apply/canadian-experience-class.html", U_OFFICES])
P(id="prog-fswp", canonical_name="Federal Skilled Worker Program",
  common_variants=["fswp", "fsw", "federal skilled worker", "federal skilled workers program"], visa_codes=["PR-EE-FSW"],
  source_urls=[B + "/services/immigrate-canada/express-entry/who-can-apply/federal-skilled-workers.html", U_OFFICES],
  source_note="Read 2026-11-16 (cached copy dated 2026-11-14).")
P(id="prog-fstp", canonical_name="Federal Skilled Trades Program",
  common_variants=["fstp", "fst", "federal skilled trades"], visa_codes=["PR-EE-FST"],
  source_urls=[B + "/services/immigrate-canada/express-entry/who-can-apply/federal-skilled-trades.html", U_OFFICES],
  source_note="Read 2026-11-16 (cached copy dated 2026-11-14).")
P(id="prog-pnp", canonical_name="Provincial Nominee Program",
  ircc_aliases=["pnp", "provincial nominee program: express entry process", "provincial nominee program: non-express entry process",
                "non-express entry"],
  common_variants=["provincial nominee programme", "enhanced pnp", "base pnp", "enhanced nomination", "base nomination", "provincial nomination"],
  visa_codes=["PR-PNP-EE", "PR-PNP-BASE"],
  note=("IRCC names the two routes by process (Express Entry and non-Express Entry). Enhanced and base are practitioner terms. "
        "Each province names its own streams, which are not in this file. Non-Express Entry is a phrase of this row, so the "
        "longer match keeps the Express Entry inside it from reading as the Express Entry row."),
  source_urls=[B + "/services/immigrate-canada/provincial-nominees/express-entry.html", B + "/services/immigrate-canada/provincial-nominees/non-express-entry.html"],
  source_note="Read 2026-11-16 (cached copies dated 2026-11-14).")
P(id="prog-family-class", canonical_name="Family Class", visa_codes=["FAM-SPOUSE", "FAM-PGP", "FAM-OTHER"],
  note="IRPR 116. Sponsorship of a person outside Canada, the class with an IAD appeal right.",
  source_urls=[U_IMM5289, U_DM26_FAM])
P(id="prog-spouse-in-canada-class", canonical_name="Spouse or Common-Law Partner in Canada Class",
  common_variants=["spouse or common law partner in canada class", "inland spousal sponsorship"],
  visa_codes=["FAM-SPOUSE"], note="IRPR 123. IRCC capitalizes it differently across pages (in-Canada, in Canada).",
  source_urls=[U_IMM5289], source_note="Guide IMM 5289, read 2026-11-16.")
P(id="prog-spouse-sponsorship", canonical_name="Sponsor your spouse, partner or child",
  common_variants=["spousal sponsorship", "spouse sponsorship", "partner sponsorship", "spousal sponsorship program", "dependent child sponsorship"],
  visa_codes=["FAM-SPOUSE"],
  note="IRCC gives this no proper-noun program name. The page calls it a program to sponsor a spouse, common-law partner, conjugal partner or dependent child.",
  source_urls=[B + "/services/immigrate-canada/family-sponsorship/spouse-partner-children.html"],
  source_note="Read 2026-11-16 (cached copy dated 2026-11-08).")
P(id="prog-pgp", canonical_name="Parents and Grandparents Program",
  ircc_aliases=["pgp", "pgp program", "parents and grandparents (pgp) program"],
  common_variants=["parent and grandparent program", "parents and grandparents sponsorship"],
  visa_codes=["FAM-PGP"], note="Intake paused since 2026-07-15. A letter that says the sponsor was invited after that date is a fact for the RCIC to check.",
  source_urls=[B + "/news/notices/responsibly-manage-parent-grandparent-program.html", B + "/services/immigrate-canada/family-sponsorship/sponsor-parents-grandparents.html"],
  source_note="Notice dated 2026-07-15, read 2026-11-16.")
P(id="prog-other-relatives", canonical_name="Sponsor your relatives",
  ircc_aliases=["sponsor your other relatives"], common_variants=["other relatives sponsorship", "orphaned relative sponsorship", "lonely canadian"],
  visa_codes=["FAM-OTHER"],
  note="No proper-noun program name. Lonely Canadian is practitioner shorthand for the IRPR 117(1)(h) case, not IRCC wording.",
  source_urls=[B + "/services/immigrate-canada/family-sponsorship/other-relatives.html", U_EXPLORE],
  source_note="Read 2026-11-16 (cached copy dated 2026-11-14).")
P(id="prog-in-canada-asylum", canonical_name="In-Canada Asylum Program",
  ircc_aliases=["claim for refugee protection", "refugee protection claim", "claiming asylum from within canada"],
  common_variants=["asylum claim", "refugee claim", "in canada asylum program"], visa_codes=["REF-CLAIM"],
  note="IRCC changes the asylum application from 2026-11-03. The Refugee Protection Division of the IRB decides the claim.",
  source_urls=[B + "/services/asylum/in-canada.html", U_DM26_REF, U_IRB])
P(id="prog-refugee-resettlement", canonical_name="Refugee Resettlement Program",
  ircc_aliases=["refugee and humanitarian resettlement program", "resettlement program"],
  visa_codes=["REF-RESETTLE"],
  note="IRCC uses Refugee Resettlement Program (2026 binder) and Refugee and Humanitarian Resettlement Program (How Canada's refugee system works). Both are accepted.",
  source_urls=[U_DM26_REF, U_HOWSYS])
P(id="prog-gar", canonical_name="Government-Assisted Refugees program",
  ircc_aliases=["government-assisted refugee program", "government-assisted refugees", "gar program", "gar"],
  common_variants=["government assisted refugees program"], visa_codes=["REF-RESETTLE"],
  note="IRCC writes it singular (Government-Assisted Refugee Program) in the operational manual and plural on the applicant page. Referral only.",
  source_urls=[B + "/services/refugees/resettle-refugee/government-assisted-refugee-program.html", U_RESETTLE_OB])
P(id="prog-psr", canonical_name="Private Sponsorship of Refugees Program",
  ircc_aliases=["private sponsorship of refugees", "privately sponsored refugees", "psr program", "psr"],
  visa_codes=["REF-RESETTLE"],
  note="Sponsor types are Sponsorship Agreement Holders, Groups of Five and Community Sponsors. Groups of Five and Community Sponsors are paused.",
  source_urls=[B + "/services/refugees/sponsor-refugee/private-sponsorship-program.html", U_DM26_REF])
P(id="prog-bvor", canonical_name="Blended Visa Office-Referred Program",
  ircc_aliases=["blended visa office-referred", "blended visa office referral", "bvor program", "bvor"],
  common_variants=["blended visa office referred program"], visa_codes=["REF-RESETTLE"],
  source_urls=[B + "/services/refugees/sponsor-refugee/private-sponsorship-program/blended-visa-office-program.html",
               "https://ircc.canada.ca/english/helpcentre/answer.asp?qnum=770&top=11", U_RESETTLE_OB])
P(id="prog-jas", canonical_name="Joint Assistance Sponsorship Program",
  ircc_aliases=["joint assistance sponsorship", "jas"], visa_codes=["REF-RESETTLE"],
  source_urls=["https://ircc.canada.ca/english/helpcentre/answer.asp?qnum=095&top=11", U_RESETTLE_OB])
P(id="prog-rap", canonical_name="Resettlement Assistance Program", visa_codes=["REF-RESETTLE"],
  note="Income support for resettled refugees. RAP is left out as an alias, since it collides with ordinary text.",
  source_urls=[U_HOWSYS])
P(id="prog-ifhp", canonical_name="Interim Federal Health Program", ircc_aliases=["ifhp"], visa_codes=["REF-RESETTLE", "REF-CLAIM"],
  source_urls=["https://ircc.canada.ca/english/helpcentre/answer.asp?qnum=769&top=11"])
P(id="prog-empp", canonical_name="Economic Mobility Pathways Pilot", ircc_aliases=["empp"],
  note="Economic pathway for skilled refugees, outside the 17 codes.", source_urls=[U_DM26_REF])
P(id="prog-hc", canonical_name="Humanitarian and compassionate considerations",
  ircc_aliases=["humanitarian and compassionate", "h&c"],
  common_variants=["humanitarian and compassionate grounds", "h and c", "h&c application"], visa_codes=["HC-PR"],
  source_urls=[B + "/services/application/application-forms-guides/humanitarian-compassionate-considerations.html"],
  source_note="Read 2026-11-16 (cached copy dated 2026-11-11).")
P(id="prog-aip", canonical_name="Atlantic Immigration Program", ircc_aliases=["aip"],
  note="Outside the 17 codes. In force 2022-01-01.", source_urls=[B + "/services/immigrate-canada/atlantic-immigration.html"])
P(id="prog-aipp", canonical_name="Atlantic Immigration Pilot Program", ircc_aliases=["atlantic immigration pilot", "aipp"],
  status="former", replaced_by="prog-aip", note="Closed 2021-12-31, last applications 2022-03-05.",
  source_urls=[B + "/corporate/publications-manuals/operational-bulletins-manuals/updates/2022-atlantic-immigration-program.html"],
  source_note="Update dated 2022-04-07, read 2026-11-16.")
P(id="prog-start-up-visa", canonical_name="Start-up Visa Program", ircc_aliases=["start-up visa"], common_variants=["startup visa"],
  note=("Outside the 17 codes. IRCC stopped new applications at 11:59 p.m. on 2025-12-31, except from applicants with a "
        "valid 2025 commitment from a designated organization, and plans a new entrepreneur pilot. Kept current while those "
        "applications are processed."),
  source_urls=[U_OFFICES, U_SUV_END], source_note="Notice dated 2025-12-19, read 2026-11-16.")
P(id="prog-self-employed", canonical_name="Self-Employed Persons Program", common_variants=["self employed persons program"],
  note="Outside the 17 codes.", source_urls=[U_OFFICES])
P(id="prog-hcwip", canonical_name="Home Care Worker Immigration Pilots",
  common_variants=["home care worker immigration pilot", "home care worker pilots", "home care worker pilot"],
  note="Outside the 17 codes. PR for home child care providers and home support workers, listed on the explore programs page.",
  source_urls=[U_EXPLORE, U_HCWIP], source_note="Explore programs page modified 2026-09-08, read 2026-11-16.")
P(id="prog-caring-pathways", canonical_name="Caring for Children and Caring for People with High Medical Needs pathways",
  ircc_aliases=["caring for children pathway", "caring for people with high medical needs pathway",
                "caring for children program", "caring for people with high medical needs program"],
  status="former", replaced_by="prog-hcwip",
  note=("Both programs ended on 2019-06-18, and IRCC still processes complete applications sent before then (CPC Edmonton). "
        "The IRCC pages point to the 2019 Home Child Care Provider and Home Support Worker pilots, which the 2026 explore "
        "programs page no longer lists. replaced_by is the caregiver pathway that page lists."),
  source_urls=[U_CARE_CHILD, U_CARE_HMN, U_OFFICES, U_EXPLORE],
  source_note="Caregiver pages modified 2023-09-25, explore programs page modified 2026-09-08, read 2026-11-16.")
P(id="prog-rcip", canonical_name="Rural Community Immigration Pilot", ircc_aliases=["rural community immigration class"],
  common_variants=["rcip", "rural community immigration pilots"],
  note=("Outside the 17 codes. PR for skilled workers in certain smaller communities. The IRPR amendment in force "
        "2026-10-23 prescribes it as the rural community immigration class (IRPR 87.4 to 87.46), so the class name is an alias."),
  source_urls=[U_EXPLORE, U_RCIP, U_IRPR_87_4],
  source_note=("Explore programs page modified 2026-09-08, read 2026-11-16. IRPR 87.4(1), consolidation current to "
               "2026-10-29, read 2026-11-19 (found by the first X-37 law check)."))
P(id="prog-fcip", canonical_name="Francophone Community Immigration Pilot", common_variants=["fcip", "francophone community immigration pilots"],
  note="Outside the 17 codes. PR for skilled French-speaking workers in certain smaller Francophone minority communities.",
  source_urls=[U_EXPLORE, U_FCIP], source_note="Explore programs page modified 2026-09-08, read 2026-11-16.")

# ---------- checks ----------
seen = {}
for r in rows:
    for a in r["ircc_aliases"] + r["common_variants"]:
        assert a == a.lower() and a.strip() == a and a, (r["id"], a)
    assert fold(r["canonical_name"]) not in [fold(a) for a in r["ircc_aliases"] + r["common_variants"]], r["id"]
    for a in [r["canonical_name"].lower()] + r["ircc_aliases"] + r["common_variants"]:
        k = fold(a)
        if k in seen and seen[k] != r["id"]:
            raise SystemExit(f"alias clash: {a} in {seen[k]} and {r['id']}")
        seen[k] = r["id"]
    for t in (r["note"] or "", r["source_note"] or "", r["canonical_name"], r["successor_note"] or ""):
        assert "—" not in t and ";" not in t, (r["id"], t)
    assert r["kind"] in ("office", "program", "organization"), r["id"]
    assert r["letter_addressee"] in (("n/a",) if r["kind"] == "program" else ("yes", "on_request", "no")), r["id"]
ids = [r["id"] for r in rows]
assert len(set(ids)) == len(ids)
for r in rows:
    assert r["replaced_by"] in (None, *ids), r["id"]
    assert (r["status"] == "former") == (r["replaced_by"] is not None), r["id"]
    assert r["successor_note"] is None or (r["status"] == "former" and r["successor_note"].strip()), r["id"]
    assert r["source_urls"] and all(u.startswith("https://") for u in r["source_urls"]), r["id"]
codes = {"TR-VISIT", "TR-SUPER", "TR-STUDY", "TR-WP-EMP", "TR-WP-OPEN", "TR-PGWP", "PR-EE-CEC", "PR-EE-FSW", "PR-EE-FST",
         "PR-PNP-EE", "PR-PNP-BASE", "FAM-SPOUSE", "FAM-PGP", "FAM-OTHER", "REF-CLAIM", "REF-RESETTLE", "HC-PR"}
covered = set()
for r in rows:
    assert set(r["visa_codes"]) <= codes, r["id"]
    if r["kind"] == "program" and r["status"] == "current":
        covered |= set(r["visa_codes"])
assert covered == codes, codes - covered
for i, r in enumerate(rows):
    r["sort_order"] = (i + 1) * 10
order = ["id", "kind", "canonical_name", "ircc_aliases", "common_variants", "status", "replaced_by", "successor_note", "organization",
         "letter_addressee", "visa_codes", "note", "source_urls", "source_note", "sort_order", "last_verified"]
doc = {
    "source": ("F-F13.2 controlled vocabulary, read 2026-11-16 from canada.ca IRCC pages and the IRB site (one office relocation "
               "from news, marked). kind is office, program or organization. canonical_name is the form a draft should use. "
               "ircc_aliases are other forms seen on the cited IRCC or IRB pages, common_variants are accepted shorthand not seen there. "
               "Aliases are lowercase and unique across rows after folding diacritics, and the canonical name is never repeated as an alias. "
               "status former means IRCC no longer uses the name and replaced_by names the current row. successor_note, when set, "
               "is what the flag names instead, where the source names more than one successor. letter_addressee says whether a "
               "submission may be addressed there: yes, on_request (only when that office asked), no, or n/a for a program. "
               "visa_codes ties a row to the ref.visa_types codes it belongs to. Public facts only, no client data."),
    "ircc_vocabulary": [{k: r[k] for k in order} for r in rows],
}
with open(OUT, "w", encoding="utf-8", newline="\n") as f:
    json.dump(doc, f, ensure_ascii=False, indent=2)
    f.write("\n")
print(len(rows), "rows,", sum(r["kind"] == "office" for r in rows), "offices,", sum(r["kind"] == "program" for r in rows),
      "programs,", sum(r["kind"] == "organization" for r in rows), "organizations,", sum(r["status"] == "former" for r in rows), "former")
