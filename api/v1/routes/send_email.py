import msal
import requests
import pandas as pd
import logging
from key_vault_manager import get_key

client_id =get_key('GRAPH-CLIENT-ID')
client_secret =get_key("GRAPH-CLIENT-SECRET")
tenant_id=get_key("GRAPH-TENANT-ID")
authority=f'https://login.microsoftonline.com/{tenant_id}'
scopes =['https://graph.microsoft.com/.default']

log = logging.getLogger("firefighter")

excel_file_path = "compliance_results.xlsx"
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

def send_email(user_email, content, cc_addresses, t_codes_list, wf_fflog_id):
    try:   
        log.info(user_email) 
        log.info(cc_addresses)
        transaction_codes = "<br>".join(t_codes_list) if t_codes_list else "No transaction codes provided."
       
        access_token = get_access_token()

        user_id = "notify_fflogreview@ab-inbev.com"
        endpoint = f'https://graph.microsoft.com/v1.0/users/{user_id}/sendMail'

        html_content = content.replace('\n', '<br>')
        
        email_body = f"""
                    <p>Hi,</p>
                    <p>This is a notification regarding the firefighter log review for your recent activities.</p>
                    <p>{html_content}</p>
                    <p>Please ensure that you provide the necessary approvals from your line manager.</p>
                    <p>Best regards,<br>Firefighter Log Review Team</p>
                    """
        email_subject = f"Firefighter Log Review: Action Required, WF ID: {wf_fflog_id}"
        email_msg = {
            "message": {
                "subject": email_subject,
                "body": {
                    "contentType": "HTML",
                    "content": email_body
                },
                "toRecipients": [
                    {
                        "emailAddress": {
                            "address": user
                        }
                    } for user in user_email
                ],
                "ccRecipients": [
                    {
                        "emailAddress": {
                            "address": cc_address
                        }
                    } for cc_address in cc_addresses
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

def get_non_compliant_users(file_path):
    try:
        df = pd.read_excel(file_path)
        log.info(df)

        if "SMTP_ADDR" not in df.columns or "Compliance_Status" not in df.columns:
            raise Exception("Required columns not found in excel sheet")

        non_compliant_users =df[df["Compliance_Status"] =="Non-Match"]
        log.info(non_compliant_users)
        return non_compliant_users["SMTP_ADDR"].dropna().tolist()
    except Exception as e:
        log.error(f"Error processing Excel file: {e}")
        return []

def process_ffusers_mails():
    non_compliant_emails = get_non_compliant_users(excel_file_path)
    log.info(non_compliant_emails)
    if len(non_compliant_emails) > 0:
        for email in non_compliant_emails:
            send_email(email)
    else:
        log.info("No non-match users found.")
