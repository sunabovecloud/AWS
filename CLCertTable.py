import json
import hashlib
import boto3

debug = True
class CLCertTable:
    region_nm = "us-east-2"
    client_dydb = boto3.client("dynamodb")
    resource_dydb = boto3.resource("dynamodb")
    # CertTable info
    cert_table_nm =  "CertTable" 
    cert_primary_column_name = "client_id"
    cert_columns = [ "issued_on", "private_key", "public_key","description","expires" ]
    cert_item = {}
    # SessionTable info
    sess_table_nm = "SessionTable"
    sess_primary_column_name = "token_signature"
    sess_columns = ["client_id","enveloped_tm","created_tm","received_tm","session_token"]
    def __init__(self):
        pass
    def describe_certdata_table():
        pass
    def get_certdata_item( self, client_id ):
        fun = "get_certdata_item"
        try:
            print(f"=======---- {self.cert_table_nm} ----=======")
            cert_table = self.resource_dydb.Table(self.cert_table_nm)
            pr_column_nm = self.cert_primary_column_name
            db_response = cert_table.get_item(
                Key={
                      pr_column_nm:client_id
                }
            )
        except:
            if(debug):
                print( "Error: Table: {} Not Found or Invalid Primary Column: {} - Func: {} ".format( self.cert_table_nm, self.cert_primary_column_name,fun) )
            return False
        if( not db_response.get("Item") ):
            if(debug):
                print( "ERROR NO Matching Client Found" ) 
            return False
        self.cert_item = db_response["Item"]
        return True
    def get_certdata_by_key( self, key ):
        fun = "get_certdata_by_key"
        print( self.cert_item )
        ret = self.cert_item.get(key)
        if( not ret  ):
            if(debug):
                print( f"ERROR NO Matching Client Found - {fun} - {key}" ) 
            return False
        if(debug):
            print( ret )
        return ret
