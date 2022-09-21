from inspect import Attribute
import json
import hashlib
import boto3
import random
from datetime import timezone
import datetime
from boto3.dynamodb.conditions import Key, Attr

# get_sessdata_item( self, token_signature )
# get_sessdata_by_key( self, key )
debug = True
expiry_inMin = 4
class CLSessTable:
    region_nm = "us-east-2"
    client_dydb = boto3.client("dynamodb")
    resource_dydb = boto3.resource("dynamodb")
    # SessTable info
    sess_table_nm =  "SessTable" 
    sess_primary_column_name = "token_signature"
    sess_columns = ["client_id","enveloped_tm","created_tm","received_tm","session_token"]
    sess_item = {}
# ===== Fun
    def __init__(self):
        pass
# ===== Fun
    def has_sess_expired(self, tm1, expiry_inMinutes):
        strdt1 = tm1.replace(":", "-").replace(" ","-")
        strAr1 = strdt1.split('-')
        if( len(strAr1) != 6 ):
            return "Invalid"
        strdt2 = self.get_sessdata_by_key("received_tm")
        if( strdt2 ):
            strdt2.replace(":", "-").replace(" ","-")
            strAr2 = strdt2.split('-')
            if( len(strAr2) == 6 ):
                dt2 = datetime.datetime( int(strAr2[0]), int(strAr2[1]), int(strAr2[2]), int(strAr2[3]), int(strAr2[4]), int(strAr2[5]) )
                dt1 = datetime.datetime( int(strAr1[0]), int(strAr1[1]), int(strAr1[2]), int(strAr1[3]), int(strAr1[4]), int(strAr1[5]) )
                dtdiff = dt1 - dt2 #nowreceived - lastreceived
                if( (dtdiff.total_seconds() / 60) <= (expiry_inMinutes) ):
                    return "NotExpired"
                else:
                    return "Expired"
        return "FirstTime"
# ===== Fun    
    def create_sessdata_token( self ):
        dt = datetime.datetime.now(timezone.utc)
        rand = str(random.randint(1, 1000))
        rand += ( (str(dt)).replace(" ","").replace(":","").replace("-","").replace("+","").replace(".","") ) + rand
        randAr =  list(rand) 
        random.shuffle( randAr )
        rand = "".join( randAr )
        h = hashlib.new('md5')
        h.update( rand.encode() )
        digst = "{}".format(h.hexdigest())
        rand = digst[0:24]
        chrr = chr( 97 + random.randint(0, 25)) 
        for i in range(24):
            ran = random.randint(0, 25)
            u = chr( 65 + ran )
            l = chr( 97 + ran )
            rana = random.randint(0, 2)
            if( rana == 0 ):
                pass
            elif( rana == 1 ):
                rand = rand [:i] + l + rand [i + 1:]
                chrr = chr( 65 + random.randint(0, 25)) 
            else:
                rand = rand [:i] + u + rand [i + 1:]
                chrr = chr( 97 + random.randint(0, 25))
        arand = rand + "." + chrr + "."
        dt1 = datetime.datetime.now(timezone.utc)
        dt2 = datetime.datetime.now(timezone.utc)
        rand = "{}USA{}".format(dt1,dt2)
        randAr = list(rand) 
        random.shuffle( randAr )
        rand = "".join( randAr )
        h = hashlib.new('sha256')
        h.update( rand.encode() )
        digst = "{}".format( h.hexdigest() )
        lng = len( digst ) 
        for i in range( lng ):
            ran = random.randint(0, 25)
            u = chr( 65 + ran )
            l = chr( 97 + ran )
            rana = random.randint(0, 2)
            if( rana == 0 ):
                pass
            elif( rana == 1 ):
                digst = digst [:i] + l + digst [i + 1:]
            else:
                digst = digst [:i] + u + digst [i + 1:] 

        stoken = arand + digst + str(random.randint(0, 10000))
        return stoken
# ===== Fun  
    def get_token_signature( self, stoken ):
        h = hashlib.new('md5')
        h.update( stoken.encode() )
        return  "{}".format(h.hexdigest())
# ===== Fun     
    def is_token():
        if(stoken[24] + stoken[26] == ".." and len(stoken) > 90 and len(stoken) < 97 ):
            return True
        return False
# ===== Fun  
    def describe_sessdata_table():
        pass
# ===== Fun  
    def get_sessdata_item( self, token_signature ):
        fun = "get_certdata_item"
        try:
            print(f"=======---- {self.sess_table_nm} ----=======")
            sess_table = self.resource_dydb.Table(self.sess_table_nm)
            pr_column_nm = self.sess_primary_column_name
            db_response = sess_table.get_item(
                Key={
                      pr_column_nm:token_signature
                }
            )
        except:
            if(debug):
                print( "Error: Table: {} Not Found or Invalid Primary Column: {} - Func: {} ".format( self.sess_table_nm, self.sess_primary_column_name,fun) )
            return False
        if( not db_response.get("Item") ):
            if(debug):
                print( "ERROR NO Matching Client Found" ) 
            return False
        self.sess_item = db_response["Item"]
        return True
# ===== Fun  
    def get_sessdata_by_key( self, key ):
        fun = "get_sessdata_by_key"
        print( self.sess_item )
        ret = self.sess_item.get(key)
        if( not ret  ):
            if(debug):
                print( f"ERROR NO Matching Client Found - {fun} - {key}" ) 
            return False
        if(debug):
            print( ret )
        return ret
        
    def processToken(self, stoken ):
        if( not self.is_token( stoken ) ):
            return {"status code":"400", "errorMessage:":"Bad Request: You submitted invalid input"} # bad request
        sigToken = self.get_token_signature( stoken )
        if( not self.get_sessdata_item( sigToken ) ):
            return {"status code":"401", "errorMessage:":"Unauthorized: The access token is invalid"} # Unauthorized request
        dTime01 = (str(datetime.datetime.now(timezone.utc)))[0:19]
        if( self.has_sess_expired(dTime01, expiry_inMin) == "Expired" ):
            return {"status code":"401", "errorMessage:":"Unauthorized: The access token is expired"} # Unauthorized request
        if( self.update_sessdata_attr_(sigToken, "received_tm", dTime01 ) ):
            return { "code":"200", "description": "OK" }
        #return { "code":"401","description":"Unauthorized","WWW-Authenticate":"Bearer error=\"invalid_token\"\n  error_description=\"The access token is invalid\"","Content-type":"application/json"}
        #update attribute    
        
# ===== Fun  
    def get_sessdata_query_key( self, KEY, data ):
        fun = "get_sessdata_query_key"
        sess_table = self.resource_dydb.Table(self.sess_table_nm)
        #from boto3.dynamodb.conditions import Key
        db_response = sess_table.query(
            KeyConditionExpression=Key(KEY).eq(data)
        )
        print( db_response )
# ===== Fun  
    def get_sessdata_scan_allexpired(self, mdate):
        #from boto3.dynamodb.conditions import Key, Attr
        sess_table = self.resource_dydb.Table(self.sess_table_nm)
        db_response = sess_table.scan(
           FilterExpression=Attr('received_tm').lt("mdate")
        )
        return db_response 
# ===== fun 
    def del_sessdata_by_key_val(self, dkey, dval):
        sess_table = self.resource_dydb.Table(self.sess_table_nm)
        response = sess_table.scan()
        db_response = response['Items']
        for rec in db_response:
            if( rec[dkey] == dval ):
                if rec[dkey] == dval:
                    sess_table.delete_item(
                     Key = {
                       self.sess_primary_column_name : rec["token_signature"]
                     }
                )
        return True; 
# ===== Fun  
    def get_sessdata_del_allexpired(self, response_rec):
        for x in response_rec:
            x[token_signature]
        #table.delete() entire table
        pass
# ===== Fun  
    def update_sessdata_attr_(self, pkey, dkey, dval):
        sess_table = self.resource_dydb.Table(self.sess_table_nm)
        pr_column_nm = self.sess_primary_column_name
        sess_table.update_item(
             Key={sess_primary_column_name: pkey},
             AttributeUpdates={
               dkey : dval
             },
        )
        return True
# =========== fun
    def new_sessdata_client_id(self, client_id ):
        dTime01 = (str(datetime.datetime.now(timezone.utc)))[0:19]
        return self.new_sessdata_from_request( client_id, dTime01, dTime01 )
# =========== fun        
    def new_sessdata_from_request(self, client_id, enveloped_tm, created_tm ):
        session_token = self.create_sessdata_token()
        h = hashlib.new('md5')
        h.update( session_token.encode() )
        token_signature = "{}".format( h.hexdigest() )
        sess_table = self.resource_dydb.Table(self.sess_table_nm)
        pr_column_nm = self.sess_primary_column_name
        dTime01 = (str(datetime.datetime.now(timezone.utc)))[0:19]
        db_response = sess_table.put_item(
            Item={
                      pr_column_nm:token_signature,
                      self.sess_columns[0]: client_id,
                      self.sess_columns[1]: enveloped_tm,
                      self.sess_columns[2]: created_tm,
                      self.sess_columns[3]: dTime01,
                      self.sess_columns[4]: session_token
                }
            )
        print( db_response )
        return db_response["ResponseMetadata"]["HTTPStatusCode"] #200
"""
        #["client_id","enveloped_tm","created_tm","received_tm","session_token"]
        sess_table = self.resource_dydb.Table(self.sess_table_nm)
        pr_column_nm = self.sess_primary_column_name
        dTime01 = (str(datetime.datetime.now(timezone.utc)))[0:19]
        db_response = sess_table.put_item(
                Key={
                      pr_column_nm:token_signature,
                      self.sess_columns[0]: client_id,
                      self.sess_columns[1]: enveloped_tm,
                      self.sess_columns[2]: created_tm,
                      self.sess_columns[3]: dTime01,
                      self.sess_columns[3]: session_token
                }
            )
        db_response["ResponseMetadata"]["HTTPStatusCode"] #200
        
        #Delete
        sess_table = self.resource_dydb.Table(self.sess_table_nm)
        pr_column_nm = self.sess_primary_column_name]
        db_response = sess_table.delete_item(
                Key={
                      pr_column_nm:token_signature
                }
            )
        db_response["ResponseMetadata"]["HTTPStatusCode"] #200
        
        #Describe
        db_response = client_dydb.describe_table(TableName = self.sess_table_nm)
        #db_response
        
        #query 
        sess_table = self.resource_dydb.Table(self.sess_table_nm)
        from boto3.dynamodb.conditions import key
        db_response = sess_table.query(
            KeyConditionExpression=key('').eq("")
        )
        
"""
        