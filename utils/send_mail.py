import msal
import requests
import pandas as pd
import logging
from key_vault_manager import get_key
from config import REVERT_WITHIN_DAYS,mail_box,DAYS_COUNT
log = logging.getLogger("firefighter")

client_id =get_key('GRAPH-CLIENT-ID')
client_secret =get_key("GRAPH-CLIENT-SECRET")
tenant_id=get_key("GRAPH-TENANT-ID")
authority=f'https://login.microsoftonline.com/{tenant_id}'
scopes =['https://graph.microsoft.com/.default']


COMMON_GREETING = "Hello Firefighter User,<br/><br/>"

COMMON_CLOSURE = f"""
                Can you please revert within {REVERT_WITHIN_DAYS} days of receiving the email?<br/><br/>
                Without the required information, the logs will be marked as a failure.<br/>
                Thanks for your attention to this.
                """

TEMPLATES = {
    "action_code_template": """
        {COMMON_GREETING}
        While reviewing the firefighter logs you executed, we noticed additional transactions were performed beyond the initial request.<br/><br/>
        Here are the transactions that were not requested or approved:<br/>
        {transactions_list}
        Please provide the following to proceed:<br/>
        <ul>
            <li>Business justification/reason for the additional access.</li>
            <li>List of activities performed using these transactions.</li>
        </ul>
        If you have prior approval for these transactions, attach the document. If not, we'll need manager approval after your justification.<br/><br/>
        {COMMON_CLOSURE}
    """,

    "time_duration_template": """
        {COMMON_GREETING}
        As part of reviewing the firefighter logs which have been executed by you, we noticed that you requested FF access for more than {DAYS_COUNT} business days.<br/><br/>
        Requesting you to provide the below set of details to process the fighter logs:<br/>
        <ul>
            <li>Business justification for requesting FF access for more than {DAYS_COUNT} days.</li>
            <li>List of transactions performed during this time.</li>
        </ul>
        If you have prior approval for these transactions, attach the document. If not, we'll need manager approval after your justification.<br/><br/>
        {COMMON_CLOSURE}
    """,

    "time_duration_action_code_template": """
        {COMMON_GREETING}
        While reviewing the firefighter logs you executed, we noticed additional transactions were performed beyond the initial request. In addition, you requested FF access for more than {DAYS_COUNT} business days.<br/><br/>
        Here are the transactions that were not requested or approved:<br/>
        {transactions_list}
        Please provide the following to proceed:<br/>
        <ul>
            <li>Business justification/reason for the additional access.</li>
            <li>List of activities performed using these transactions.</li>
            <li>Business justification for requesting FF access for more than {DAYS_COUNT} days.</li>
        </ul>
        If you have prior approval for these transactions, attach the document. If not, we'll need manager approval after your justification.<br/><br/>
        {COMMON_CLOSURE}
    """
}


def get_access_token():
    app = msal.ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret,
    )
    
    result = app.acquire_token_for_client(scopes)
    if 'access_token' in result:
        return result['access_token']
    else:
        raise Exception(f"Error acquiring token: {result.get('error_description')}")

def get_email_body(template_type, transactions):
    try:
        transactions_list = (
            "<ul>" + "".join(f"<li>{t}</li>" for t in transactions) + "</ul>"
            if transactions
            else "No transaction codes provided."
        )
        return TEMPLATES[template_type].format(transactions_list=transactions_list,COMMON_GREETING=COMMON_GREETING,
            COMMON_CLOSURE=COMMON_CLOSURE, REVERT_WITHIN_DAYS=REVERT_WITHIN_DAYS,DAYS_COUNT=DAYS_COUNT)
    except Exception as e:
        log.error(f"Error in get_email_body: {e}")  
        return ""
    
def determine_template(time_duration_text, action_codes_text):
    try:
        time_duration_text = time_duration_text.lower()
        action_codes_text = action_codes_text.lower()
        
        if time_duration_text == "not-match" and action_codes_text == "not-match":
            return "time_duration_action_code_template"
        elif time_duration_text == "not-match":
            return "time_duration_template"
        elif action_codes_text == "not-match":
            return "action_code_template"
        return None
    except Exception as e:
        log.info(f"Error in determine_template: {e}")
        return None

def send_email(user_email, cc_addresses, 
                           time_duration_text, action_codes_text, not_matching_tcodes,connector,valid_logon_time,ff_func_value):
    try:
        access_token = get_access_token()
        endpoint = f"https://graph.microsoft.com/v1.0/users/{mail_box}/sendMail"
        template_type = determine_template(time_duration_text, action_codes_text)
        email_body = get_email_body(template_type, not_matching_tcodes) if template_type else None
        if not template_type or not email_body:
            log.info(f"Email not sent: Template is {template_type}, Email Body is {'empty' if not email_body else 'present'}.")
            return  # Skip sending the email
        log.info(f"Proceeding with email sending using template: {template_type}.")

        email_subject = f"Firefighter Log Review: Action Required, FFID: {ff_func_value}, {connector}, {valid_logon_time}"
        email_msg = {
            "message": {
                "subject": email_subject,
                "body": {
                    "contentType": "HTML",
                    "content": email_body
                },
                "toRecipients": [
                    {"emailAddress": {"address": user}} for user in user_email
                ],
                "ccRecipients": [
                    {"emailAddress": {"address": cc}} for cc in cc_addresses
                ] if cc_addresses else []
            }
        }
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        response = requests.post(endpoint, json=email_msg, headers=headers)
        if response.status_code == 202:
            log.info(f"Email sent successfully to {user_email} !")
        else:
            log.info(f"Error sending email to {user_email}: {response.status_code}")
            log.info(response.text)
    except Exception as e:
        log.error(e)