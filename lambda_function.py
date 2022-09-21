import json
import hashlib
import boto3
from datetime import timezone
import datetime

from CLCertTable import CLCertTable
from CLSessTable import CLSessTable

debug = True 

def lambda_handler(event, context):
    # TODO implement 
    certTbl = CLCertTable()
    certTbl.get_certdata_item("Temp2")
    certTbl.get_certdata_by_key("private_key")
    sessTbl = CLSessTable()
    stoken = sessTbl.create_sessdata_token()
    toksig = sessTbl.get_token_signature( stoken )
    print( toksig )
    sessTbl.get_sessdata_query_key( "token_signature", "mockup_signature" )
    dt1 = datetime.datetime.now(timezone.utc)
    two_days_ago = datetime.datetime.now() - datetime.timedelta(hours = 48)
    print(f"-------------{two_days_ago}")
    #data = sessTbl.get_sessdata_scan_allexpired( ("{}".format(dt1))[0:19] )
    #print( data )
    ##result = sessTbl.new_sessdata_client_id("max-123")
    ##print( result )
    #sessTbl.processToken( )
    sessTbl.del_sessdata_by_key_val("client_id","max-123")
    print("-------------")
    
    h = hashlib.new('md5')
    h.update('HRaB7VWGLT6p6S2xVVnoqf2X/nU7GTX01GINzcm8z2Jk7jqFpJLAj0ZKxDYSMLLpFXIlg2EJ6oPBE4dW1JrtKPPuCVMLeeVopXUZp2KVnbpmozd+Ydyjyz36PHmyaKOWDdW2lYPa4RFLxyUr/pQi7ktPDKLY5aX3SK8yZDHyEtNO3l1SH/Jy8NjPJzRsbiSidDIAkuUF7muTSqPWtgSv5qpsW4idSVE5m2KVVNGflb9Eqv/IDs6kTjtVqVymP05ZkW5D2IkyPNwztSeGWQqF1rtjFTHi1XhUjX/72hbt4Qsa57SaeZzx93mw90GjAs4/deBQtbEodz1CvVMFWeVvGn0H675TY/DgMxqo22DQpQPeQZCMnvCtSuUBm0PaXAfNyNmKcmzg7lli8slmdfN8SRv3TdpWiFipCTzkM/VLmBx3URYo67/pdyoa634SAqqqqTtDWgdgYluK1rW0FiH/TquMfnZvNkQNKWfJOOYNokXNQGjzJNZNUcG6xNvb4pHOqqtmw1jdfZsIEDs56pCxl+SXpcrAITyLzRJY4+6nR9RBPQZ++ktjeTJVdWpfwAulckhEWc3lcalTHPaH1csm2xXsECk2euO8rR/fP1Gi4hR5y40Mw5F4WyWrnUobVCOyMw9evwOklAoa+xQHhkm8j8TNk1G/Rv3dO+qlN6gezGI='.encode())
    print(f"============= {h.hexdigest()} ============")
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda to My friends and best friends!')
    }





