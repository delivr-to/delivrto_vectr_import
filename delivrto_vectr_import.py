import os, re, json, argparse, datetime
from datetime import datetime, timezone

### VECTR API ###
from dotenv import dotenv_values
from vectrapi.models import TestCase, Campaign
from vectrapi.vectr_api_client import VectrGQLConnParams, \
    create_assessment, \
    create_campaigns, \
    create_test_cases, \
    get_org_id_for_campaign_and_assessment_data, \
    get_assessment_by_name, \
    get_campaign_by_name

VECTR_CONFIG_FILE = "vectr.env"

SUPPORTED_SECURITY_TOOL_INTEGRATIONS = [ "Sublime", "Defender" ]

#################
"""
Print banner
"""
def print_banner():
    banner = """                                        
                    *.                  
               .*****.....              
           **********..........         
       **************..............     
     ,,,.......................... ..   
     ,,,,,,, ........................   
     ,,,,,,,,,,,......... ...........   
     ,,,,,,,,,,,,,,,,................   delivr.to VECTR v9 results importer 
     ,,,,,,,,,,,,,,,,................   
     ,,,,,,,,,,,,,,,,................   https://delivr.to
     ,,,,,,,,,,,,,,,,................   
       ,,,,,,,,,,,,,,..............     
           .,,,,,,,,,..........         
                ,,,,,......             
                    ,.                  
             
"""
    print(banner)

"""
VECTR Connection Class Object
"""
class vectr_connection():
    def __init__(self, org_name, connection_params, target_db, campaign_name, campaign_id):
        self.org_name = org_name
        self.connection_params = connection_params
        self.target_db = target_db
        self.campaign_name = campaign_name
        self.campaign_id = campaign_id

"""
Initialise VECTR connection
"""
def initialise_vectr_connection():
    print("\n[*] Initialising VECTR API:")
    
    env_config = dotenv_values(VECTR_CONFIG_FILE)
    org_name=env_config.get("ORG_NAME")

    connection_params = VectrGQLConnParams(
        api_key=env_config.get("API_KEY"),
        vectr_gql_url=env_config.get("VECTR_GQL_URL")
    )
    org_id = get_org_id_for_campaign_and_assessment_data(
        connection_params=connection_params,
        org_name=org_name
    )
    target_db = env_config.get("TARGET_DB")
    assessment_name = env_config.get("ASSESSMENT_NAME")
    campaign_name = env_config.get("CAMPAIGN_NAME")

    print(f"  - Assessment Name: {assessment_name}")
    print(f"  - Target DB: {target_db}")

    try:
        assessment_id = get_assessment_by_name(connection_params, target_db, assessment_name)
        print(f"  - Using existing assessment with ID: {assessment_id}")
    except RuntimeError as e:
        created_assessment_detail = create_assessment(connection_params, target_db, org_id, assessment_name)
        assessment_id = created_assessment_detail.get(assessment_name).get("id")
        print(f"  - Created assessment with ID: {assessment_id}")

    try:
        campaign_id = get_campaign_by_name(connection_params, target_db, campaign_name)
        print(f"  - Using existing campaign with ID: {campaign_id}\n")
    except RuntimeError as e:
        cpgn = { campaign_name: Campaign(name=campaign_name, test_cases=[]) }
        created_campaigns = create_campaigns(
            connection_params,
            target_db,
            org_id,
            cpgn,
            assessment_id
        )
        campaign_id = created_campaigns.get(campaign_name).get("id")
        print(f"  - Created campaign with ID: {campaign_id}\n")
    
    return vectr_connection(org_name, connection_params, target_db, campaign_name, campaign_id)

"""
Fetch mail type for API or UI results JSON
"""
def get_mail_type(mail_type):
    if mail_type in ['as_link', 'Link']:
        return 'Link'
    elif mail_type in ['as_attachment', 'Attachment']:
        return 'Attachment'
    elif mail_type in ['as_body', 'Body']:
        return 'Body'
    else:
        return None

"""
Enumerate email tests in input JSON
"""
def enumerate_email_tests(vectr_con, results_json, step=False, debug=False):
    emails_uploaded = []
    if step:
        for email_json in results_json:
            delivery_type = get_mail_type(email_json['mail_type'])

            if not user_prompt_confirms_continue(f"[*] Process file '{file_name}' sent as {delivery_type}? [Y/n]"):
                continue
            vectr_test_case = generate_vectr_test_case(vectr_con, email_json, debug)
            if vectr_test_case:
                if add_test_cases_to_vectr(vectr_con, [vectr_test_case]):
                    emails_uploaded.append(email_json['email_id'])
            else:
                print(f"[!] Failed to process '{file_name}' sent as {delivery_type}")
                continue
    else:
        email_test_cases = []
        for email_json in results_json:
            file_name = email_json['payload_name']
            
            delivery_type = get_mail_type(email_json['mail_type'])

            vectr_test_case = generate_vectr_test_case(vectr_con, email_json, debug)
            if debug:
                print(f"    [-] Test Case Data:")
                print(vectr_test_case)
            if vectr_test_case:
                email_test_cases.append(vectr_test_case)
                print(f"[+] Processed '{file_name}' sent as {delivery_type}")
            else:
                print(f"[!] Failed to process '{file_name}' sent as {delivery_type}")
                continue
        if add_test_cases_to_vectr(vectr_con, email_test_cases):
            emails_uploaded.extend([email['email_id'] for email in results_json])

    return emails_uploaded

def user_prompt_confirms_continue(message):
    answer = input(message)
    if answer.lower() in ["y", "yes"]:
        return True
    if not answer: return True
    return False

def generate_vectr_test_case(vectr_con, email_json, debug):
    email_id = ""
    file_name = ""
    delivery_type = ""
    mitre_id = ""
    detecting_tools = ""
    activity_logged = "TBD"
    was_detected = False
    try:
        email_id = email_json['email_id']
        file_name = email_json['payload_name']
        delivery_type = get_mail_type(email_json['mail_type'])
        payload_description = email_json.get('payload_description', "")
        if re.match(r"^\d{10}$", email_json['sent']):
            sent_epoch = int(email_json['sent']) * 1000
        else:
            sent_epoch = int(datetime.strptime(email_json['sent'], '%Y-%m-%d %H:%M').replace(tzinfo=timezone.utc).timestamp()) * 1000
    
        if delivery_type == 'Link':
            mitre_id = 'T1566.002'
        elif delivery_type == 'Attachment':
            mitre_id = 'T1566.001'
        else: #body
            mitre_id = 'T1566'
        
        tags = [delivery_type]
        payload_tags = email_json.get('payload_tags', [])
        tags.extend(payload_tags)
        description = f"""**Email ID**: {email_id}
**Delivery type**: {delivery_type.capitalize()}
**Description**: {payload_description}
"""
        references = ",".join(email_json.get('payload_references', []))
        outcome_notes = ""

        if 'clicks' in email_json and len(email_json['clicks']) > 0:
            tags.append("Clicked")
            outcome_notes+="**Clicks:**\n\n"
            outcome_notes+="| Timestamp | Method | User Agent | Source IP |\n"
            outcome_notes+="| - | - | - | - |\n"
            for click in email_json.get('clicks',[]):
                ts = datetime.fromtimestamp(int(click['timestamp'])).isoformat()
                outcome_notes+=f"| {ts} | {click['http_method']} | {click['user_agent']} | {click['source_ip']} |" + "\n"
            outcome_notes+="\n\n\n"

        if 'sendgrid_reason' in email_json:
            outcome_notes+="**Gateway Response:**\n\n"
            outcome_notes+=f"```\n{email_json['sendgrid_reason']}\n```\n\n\n"
        
        mail_controls = []
        for k,v in email_json.items():
            if k.startswith('mail_control_information'):
                if k == 'mail_control_information':
                    for control in v:
                        control = control.capitalize()
                        mail_controls.append((control, v[control]))
                else:
                    control = k.replace('mail_control_information.', '')
                    control = control.capitalize()
                    v = email_json[f"mail_control_information.{control}"]
                    mail_controls.append((control, v))

        for control, v in mail_controls:                
            if control in SUPPORTED_SECURITY_TOOL_INTEGRATIONS:
                control_name = control.capitalize()
                detecting_tools+=f",{control_name}"
                activity_logged="Yes"
                if control_name == "Sublime":
                    outcome_notes+=f"**Sublime:**\n\n"
                    outcome_notes+=f"Action: `{v['state']}`\n\n"
                    if v['flagged_rules']:
                        was_detected=True
                        tags.append(control_name)
                        outcome_notes+="Rules:\n"
                        for rule in v['flagged_rules']:
                            outcome_notes+=f" - `{rule['name']}`"
                            outcome_notes+="\n"
                if control_name == "Defender":
                    outcome_notes+=f"**Defender**\n\n"
                    outcome_notes+=f"Action: `{v['state']}`"+"\n\n"
                    if "delivered" not in v['state'].lower():
                        tags.append(control_name)
                    if v['threat_types']:
                        outcome_notes+="Threat Types:\n"
                        for tt in v['threat_types'].split(','):
                            # Defender isn't technically 'alerting' like Sublime 
                            # so we'll leave this commented out
                            # if tt != "Spam":
                            #     was_detected=True
                            outcome_notes+=f" - `{tt}`"
                            outcome_notes+="\n"
                        outcome_notes+="\n"    
                    if v['threat_names']:
                        outcome_notes+="Threat Names:\n"
                        for tt in v['threat_names'].split(','):
                            outcome_notes+=f" - `{tt}`"
                            outcome_notes+="\n"
                        outcome_notes+="\n"
                    if v['detection_methods']:
                        outcome_notes+="Detection Methods:\n\n"
                        for tt in v['detection_methods']:
                            for m in v['detection_methods'][tt]:
                                outcome_notes+=f" - `{tt}: {m}`"
                                outcome_notes+="\n"

        email_status = email_json['status'].lower()

        if 'junk' in email_status:
            tags.append("Junk")
        
        outcome = ""
        if 'delivered' in email_status:
            outcome = "NOTDETECTED" if not was_detected else "DETECTED"
        elif email_status.startswith('blocked'):
            outcome = "BLOCKED"
            if 'dropped' in email_status:
                tags.append("Dropped")
            elif 'bounced' in email_status:
                tags.append("Bounced")
        elif email_status in ["stripped", "held", "rewritten"]:
            tags.append(email_status.capitalize())
            outcome = "BLOCKED"
        elif email_status.startswith('sent'):
            outcome = "TBD"
    except Exception as e:
        print(f"[!] Failed to process email result with error: {e}")
        return False

    if debug:
        print(f"""
[+] Processing {file_name} sent as ({delivery_type})...
    [-] Email ID: {email_id}
    [-] File Name: {file_name}
    [-] Delivery Type: {delivery_type}
    [-] Outcome: {outcome}
    [-] Alerted: {"Yes" if was_detected else "No"}
    [-] Controls: {', '.join([c[0] for c in mail_controls])}
    [-] Tags: {', '.join(tags)}
""")

    return TestCase(
        Variant=f"{file_name} ({delivery_type})",
        Objective=description,
        Phase="Initial Access",
        MitreID=mitre_id,
        Tags=','.join(tags),
        Status="Completed",
        Outcome=outcome,
        OutcomeNotes=outcome_notes,
        ExpectedDetectionLayers="Email Security Gateway",
        AlertTriggered="Yes" if was_detected else "No",
        References=references,
        DetectingTools=detecting_tools,
        ActivityLogged=activity_logged,
        StartTimeEpoch=sent_epoch,
        StopTimeEpoch=sent_epoch,
        Organizations=vectr_con.org_name
    )
    

def add_test_cases_to_vectr(vectr_con, test_cases):
    created_test_cases = create_test_cases(
        vectr_con.connection_params,
        vectr_con.target_db,
        vectr_con.campaign_id,
        test_cases
    )
    return True

"""
Parse arguments
"""
parser = argparse.ArgumentParser(
    description="Upload delivr.to campaign results to VECTR."
)
parser.add_argument("--path", required=True, help="Path to delivr.to campaign output." )
parser.add_argument("--step", action="store_true", help="Prompt user for confirmation before importing each email result into VECTR." )
parser.add_argument("--no-banner", action="store_true", help="Suppress printing of banner." )
parser.add_argument("--debug", action="store_true", help="Prints debug information for each email." )
args = parser.parse_args()

no_banner = args.no_banner
step_import = args.step
email_results_path = args.path
debug = args.debug

if not no_banner:
    print_banner()

if not os.path.exists(email_results_path):
    print("[!] No delivr.to campaign results JSON found at specified path.")
    exit()

results_json = []
try:
    with open(email_results_path, 'r') as data_file:
        results_json = json.load(data_file)
        if 'emails' in results_json:
            results_json = results_json['emails']
            print(f"[*] Handling API results export.")
        else:
            print(f"[*] Handling UI results export.")
    print(f"[*] {len(results_json)} emails to be processed.")
except Exception as e:
    print("[!] Failed to process JSON from specified path, is it valid JSON?")
    exit()

vectr_con = initialise_vectr_connection()

emails_uploaded = enumerate_email_tests(vectr_con, results_json, step_import, debug)

count_of_email_results_processed = len(emails_uploaded)
print(f"\n[+] Completed results import to VECTR.")
print(f"[+] {count_of_email_results_processed} emails processed.")