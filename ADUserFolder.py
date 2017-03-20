# -*- coding: cp1251 -*-
#

# Copyright (c) 2005 Valentine Novikov(novikov@ssgpo.kz).
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.0 (ZPL).
# AD User Folder Module.

# Based on GearUserFolder - Copyright (c) 2004 Mikhail Kashkin (mailbox@xen.ru).
# All Rights Reserved.


import time
from thread import allocate_lock

import Globals
import zLOG
import OFS

from Globals import DTMLFile,MessageDialog

from OFS.Folder import Folder
from OFS.PropertyManager import PropertyManager

from AccessControl import ClassSecurityInfo
from AccessControl.Role import RoleManager
from AccessControl.User import BasicUser, BasicUserFolder, SimpleUser
from AccessControl.User import User, UserFolder, SimpleUser
from AccessControl.AuthEncoding import pw_encrypt,pw_validate
from AccessControl.ZopeSecurityPolicy import _noroles

try:
    from zExceptions import Unauthorized, BadRequest
except:
    Unauthorized=None
    BadRequest=None


import os
import ldap
from base64 import decodestring


global _from,_to

if os.name=='nt':
  _from='cp1251'
else:
  _from='utf-8'
_to='cp1251'

def _clear(r):
  return [ x for x in r  if type(x[1])==type({}) ]
  
def tl(s):
    return unicode(s,_from).encode(_to)
def fl(s):
    return unicode(s,_to).encode(_from)
    

def sql_quote(v):
    if v.find("'") >= 0: return v.replace("'", "''")
    return v
    
def _defox(s):
    ret=''
    for ch in s:
	ret+=chr(ord(ch)+144)
    return ret


# cache over Zope
cache_hash = {} # {oid -> { [cached_users, negative_cached_users] }

# we must lock before cleanup
cleanup_lock = allocate_lock()
# when we cleanup last time
global last_cleanup
last_cleanup = 0

debug = 0


   
class ADUserFolder(Folder, BasicUserFolder):
#class ADUserFolder(Folder, UserFolder):
    """AD UserFolder object."""

    meta_type='AD User Folder'
    id       ='acl_users'
    title    ='AD User Folder'

    isAnObjectManager=1
    isPrincipiaFolderish=1
    __allow_access_to_unprotected_subobjects__=1
    security = ClassSecurityInfo()
    
    # cleanup interval in seconds
    cleanup_interval = 600
    # cache check period in sec
    #check_interval = 300
    # to use full log, you can switch off cache. for more detales see doc.txt
    paranoid_log = 0 # full logging flag.
    # is passwords must bu encrypted
    encrypt_passwords = 0

    _properties = (
        {'id':'cleanup_interval', 'type':'int',},
        {'id':'encrypt_passwords', 'type':'boolean',},
        #{'id':'check_interval', 'type':'int',},
        #{'id':'default_roles', 'type':'tokens',},	
	{'id':'LDAPServer', 'type':'string',},
	{'id':'ContextName', 'type':'string',},
	{'id':'GroupBase', 'type':'string',},
	{'id':'bindUser', 'type':'string',},
	{'id':'bindPw', 'type':'string',},
	{'id':'encoding', 'type':'string',},
        )
    
    manage_options=( \
        {'label':'Contents',   'action':'manage_main'},
        {'label':'Groups',     'action':'manage_adGroups'},
	{'label':'Users',      'action':'manage_addUserForm'},
        {'label':'Properties', 'action':'manage_propertiesForm'},
        {'label':'Cache',      'action':'manage_cache'},
        {'label':'Security',   'action':'manage_access'},
        {'label':'Undo',       'action':'manage_UndoForm'},
        {'label':'Ownership',  'action':'manage_owner'},
      )
    
    manage_addUserForm = DTMLFile( 'www/addUser', globals() )
    manage_mainUsers=DTMLFile('www/mainUser', globals())
    manage_cache=DTMLFile('www/cache', globals())
    manage_adGroups=DTMLFile('www/adGroups', globals())    
    groupIndex=DTMLFile('www/groupIndex', globals())    
    if debug: 
        manage_allcache=DTMLFile('www/allcache', globals())
    
    def __init__(self):
#	UserFolder.__init__(self)
	self.LDAPServer='acme.com'
	self.ContextName='acme'
	self.GroupBase=''
	self.bindUser='testUser'
	self.bindPw='test'
	self.encoding='cp1251'
	self.local_roles={}
        pass
    
    def _open(self):
	#ld=ldap.open(self.LDAPServer)
	ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
	ld=ldap.initialize("ldaps://"+self.LDAPServer+":636")
	#print 'open',self.LDAPServer,ld
	ld.timelimit=10
	ld.set_option(ldap.OPT_REFERRALS, 0)
	ld.simple_bind_s(fl(self.bindUser+'@'+self.ContextName),fl(self.bindPw))
	return ld

    def _getCache(self, userscache):
        """Returns cache for this object.
        """
        cache = cache_hash.get(self._p_oid, None)
        if cache is None:
            cache_hash[self._p_oid] = { \
                   'cached_users' : {},  # cached users : { login -> [timestamp, user object] }
                   'negative_cached_users' : {},  # negative cached users: { login }
                  }
        return cache_hash[self._p_oid][userscache]
    
    def _getCachedUser(self, name):
        """ check if user is in negative cache or try to 
        return User object from cache """
        now=time.time()
        self._cacheCleanup() # clear caches before
        negative_cached_users = self._getCache('negative_cached_users')
        if negative_cached_users.has_key(name):
	    #print name,'negative',negative_cached_users[name],now
            negative_cached_users[name]=now
            return 1
        cached_users = self._getCache('cached_users')
        try:
	    #print name,'positive',cached_users[name][0],now
            userdata = cached_users[name]
            userdata[0]=now
            return userdata[1]
        except: 
            return None

    def _setCachedUser(self, name, object=None):
        """ set user object in cache, if `object` param 
        is None then add to negative cache """
        now = time.time()
        if object is not None:
            cached_users = self._getCache('cached_users')
            cached_users[name]=[now, object]
        else:
            negative_cached_users = self._getCache('negative_cached_users')
            negative_cached_users[name] = now

    def _clearCachedUser(self, name):
        """ delete user from all caches """
        cleanup_lock.acquire()
        cached_users = self._getCache('cached_users')
        negative_cached_users = self._getCache('negative_cached_users')
        try:
            del negative_cached_users[name]
        except:
            pass
        try:
            del cached_users[name]
        except:
            pass
        cleanup_lock.release()
        
    def _cacheCleanup(self):
        """ clear all old items """
        global last_cleanup
        now = time.time()
        cached_users = self._getCache('cached_users')
        negative_cached_users = self._getCache('negative_cached_users')
        if now - last_cleanup>self.cleanup_interval:
            timestamp = now + self.cleanup_interval
            # protect for threads
            cleanup_lock.acquire()
            try:
                for (key,value) in negative_cached_users.items():
                    if value < timestamp: del negative_cached_users[key]
                for (key,value) in cached_users.items():
                    if value[0] < timestamp: del cached_users[key]
            finally:
                cleanup_lock.release()

            last_cleanup = now
        else:        
            pass
            
    if debug:        
        def allUserCache(self, REQUEST=None, **ignore):
            return [x for x in self._getCache('cached_users')]
            #return cache_hash
            
    def getUserCache(self, REQUEST=None):
        """ list of cached users """
        cached_users = self._getCache('cached_users')
        return cached_users.keys()

    def getNegativeCache(self, REQUEST=None):
        """ list of users in negative cache """
        negative_cached_users = self._getCache('negative_cached_users')
        return negative_cached_users.keys()

    def getUserNames(self):
        """Return a list of usernames"""
        return self.local_roles.keys()

    def getUsers(self):
        """Return a list of user objects"""
        try:
            names = self.local_roles.keys()
        except:
            names = []
        return [self.getUser(n) for n in names]

    def getUser(self, name):
        """Return the named user object or None"""
        user = None
	#print 'getUser',name
        if not self.paranoid_log:
            #check for paranoid log
            user = self._getCachedUser(name)
	    #print 'from cache ',user
            if user:
		#print 'get from cache ',name,user
		if type(user)==type(1):
		  return None
                return user
        try:
	    #print self.LDAPServer,self.bindUser,self.bindPw,self.ContextName
	    ld=self._open()
	    dn=fl('DC='+self.ContextName)
	    fs=fl('(sAMAccountName='+name+')')
	    #print 'try search  ',dn,fs
	    items=_clear( ld.search_s(dn,2,fs,['dn','sAMAccountName','cn','mail']) )
	    #items=self.getListAsync(ld,dn,2,fs,['dn','sAMAccountName','cn','mail'])
	    #print items
	    #ld.close()
        except :#ldap.INVALID_CREDENTIALS :
	    #raise "ldap INVALID_CREDENTIALS!"
	    #print name,'-not found!'
            return None
        if len(items)>0:
	    #print items
	    lroles=[]
	    uname=tl( items[0][1]['sAMAccountName'][0] )
	    cn='???'
	    email=''
	    try:
	      cn=tl( items[0][1]['cn'][0] )
	    except:
	      pass
	    try:
	      email= items[0][1]['mail'][0] 
	    except:
	      pass
	    if self.local_roles.has_key(uname):
		lroles=self.local_roles[uname]
	    adroles=[]#adroles=self.adRolesOf(uname)  авпвап 
            user = ADUser(uname,\
                     password='',\
                     roles=lroles,\
		     adroles=adroles,\
                     domains=[self.LDAPServer,self.ContextName],
		     cn=cn,email=email)
	    #user.adroles=self.adRolesOf(uname)
    	self._setCachedUser(name, user)
    	#print 'cashed user',name,user
        return user

    def manage_cacheclear(self,REQUEST=None):
        """ Clear cache from ZMI """
        cleanup_lock.acquire()
        try:
            cached_users = {}
            negative_cached_users = {}
            last_cleanup = time.time()
        finally:        
            cleanup_lock.release()
        
        return self.manage_cache(REQUEST)

    def roleNormalize(self, roles):
        """ DB store roles as csv, this method convert to it """
        if type(roles) != type([]):
            if roles:
                roles=list(roles)
            else:
                roles=[]
                
        return ",".join(roles)

    def doAddUser(self, name, password, roles, domains='', REQUEST=None):
        """Create a new user"""
	u=self.getUser(name)
	if u:
    	    roles=self.roleNormalize(roles)
    	    if password is not None and self.encrypt_passwords:
        	password = self._encryptPassword(password)
	    lroles=roles.split(',')
	    self.local_roles[u.name]=lroles
	    self._p_changed=1
	    u._roles=lroles
	    u.__=''	    
	else:
	    raise "not such user!"
	if REQUEST:
	    return self.manage_addUserForm()
        #self.addRecord(name=name,password=password,roles=roles,domains='', **kw)

    def xx_doChangeUser(self, name, password, roles, domains='', **kw):
	u=self.getUser(name)
	if u:
    	    roles=self.roleNormalize(roles)
    	    if password is not None and self.encrypt_passwords:
        	password = self._encryptPassword(password)
	    self.local_roles[name]=roles.split(',')
	else:
	    raise "not such user!"    

    def doDelUsers(self, names,REQUEST=None):
        """ Source method must be undersand that `names` is sequence """	
	for n in names:
	    if self.local_roles.has_key(n):
		del self.local_roles[n]
#	self._p_changed=1
	if REQUEST:
	    return self.manage_addUserForm()
        #self.delRecord(names=names)

    def adRolesOf(self,user):
	ld=self._open()
	dn=fl(self.ContextName)
	fs=fl('(sAMAccountName='+user+')')
	items=ld.search_s(dn,2,fs,['dn','sAMAccountName','memberOf'])
	#items=self.getListAsync(ld,dn,2,fs,['dn','sAMAccountName','memberOf'])
	roles=[]
	if items[0][1].has_key('memberOf'):
	    for role in items[0][1]['memberOf']:
		role=tl(role)
		r=role.split(',')[0].split('=')[1]
		roles.append(r)	
	cn=items[0][0]
	cnl=cn.split(',')
	for cc in cnl[1:-1]:
	    roles.append( tl(cc.split('=')[1]) )
	return roles
	
    def getGroupUsers(self,group):
	" active directory groups roles "
	res=[]
	try:
	    ld=self._open()
	    if self.GroupBase:
		dn=fl('OU'+self.GroupBase+',DC='+self.ContextName)
	    else:
		dn=fl('DC='+self.ContextName)
	    fs=fl('name='+fl(group.strip())+'')
	    #print fs
	    #return [{'name':group,'description':''}]
	    ra=_clear(ld.search_s(dn,2,fs))
	    if len(ra) > 0 and len(ra[0]) >0:
	      fs=fl('memberof='+ra[0][0]+'')
	      items=_clear( self.getListAsync(ld,dn,2,fs,['dn','sAMAccountName','cn','mail']) )
	      #print items
	      #ld.close()
	      if len(items)>0:
	        for it in items:
	          d={}
	          d['name']=tl( it[1]['sAMAccountName'][0] )
	          d['description'] =tl( it[1]['cn'][0] )
	          res.append(d)
	    #print res
        except ldap.INVALID_CREDENTIALS:
	    raise "ldap INVALID_CREDENTIALS!"
	    #print name,'-not found!'
	    pass
        return res	
    
    def getUserInfo(self,name):
	"user info"
        try:
	    #print self.LDAPServer,self.bindUser,self.bindPw,self.ContextName
	    ld=self._open()
	    dn=fl('DC='+self.ContextName)
	    fs=fl('(sAMAccountName='+name+')')
	    #print 'try search  ',dn,fs
	    items=_clear( ld.search_s(dn,2,fs,['dn','sAMAccountName','cn','mail']) )
	    #items=self.getListAsync(ld,dn,2,fs,['dn','sAMAccountName','cn','mail'])
	    
	    #print items
	    #ld.close()
        except :#ldap.INVALID_CREDENTIALS :
	    #raise "ldap INVALID_CREDENTIALS!"
	    #print name,'-not found!'
	    return None
	if len(items)==0:
	  return None
	if items[0][1].has_key('mail'):
	  email=items[0][1]['mail'][0]
	else:
	  email=''
        return (tl(items[0][1]['sAMAccountName'][0]),tl(items[0][1]['cn'][0]),tl(email))

        
    def getUserDict(self,groupName):
        "users for group"
	uids={}
	try:
	    ld=self._open()
	    fs=fl('memberOf='+groupName)
	    dn=fl('DC='+self.ContextName)
	    res=_clear( ld.search_s(dn,2,fs,['sAMAccountName','cn','title','mail','telephoneNumber']) )
	    #res=_clear( self.getListAsync(ld,dn,2,fs,['sAMAccountName','cn','title','mail','telephoneNumber']) )
	    for user in res:
	        email=None
		try:
		  email=user[1]['mail'][0]
		except:
		  pass
	        uids[tl(user[1]['sAMAccountName'][0]) ]=(tl(user[1]['cn'][0]),email)
	    #uids=res
	    
	except ldap.INVALID_CREDENTIALS:
	    raise "ldap INVALID_CREDENTIALS!"
	    #print name,'-not found!'
	    pass
        return uids	
	
	
    def getByProp(self, key, value):
        # Don't return 'private' keys
	if key[0] != '_':
	 if hasattr(self, key):
	   return getattr(self, key)
	 ld=self._open()
	 ld.simple_bind_s(fl(self.bindUser+'@'+self.ContextName),fl(self.bindPw))
	 dn=fl('DC='+self.ContextName)
	 fs=fl('('+key+'='+value+')')
         #items=_clear( ld.search_s(dn,2,fs,['sAMAccountName','cn','title','mail','telephoneNumber','description','company','department','title','userAccountControl']) )
	 items=_clear( self.getListAsync(ld,dn,2,fs,['sAMAccountName','cn','title','mail','telephoneNumber','description','company','department','title','userAccountControl']) )
	 ret=[]
	 for user in items:
	    uids={}
	    if type(user[1])==type({}):
	      for k in user[1].keys():
	        uids[k]=tl(user[1][k][0])
	      ret.append(uids)
	 return ret
	 #return items
        raise KeyError, key	
    def getListAsync(self,ld,*args):
         """This version performs an asynchronous search, to allow
           results even if we hit a limit.
           It returns a list: counter followed by the results.
           If the results are truncated, counter will be set to -1.
         """
 
         #sctrl = ld.__get_server_controls__()
         #if sctrl is not None:
         #    ld.set_option(ldap.OPT_SERVER_CONTROLS, sctrl)
 
         entries = []
         partial = 0
         try:
             msgid = ld.search_ext(*args)
             type, result_list = ld.result(msgid, 0)
             while result_list:
                 for result in result_list:
                     entries.append(result)
                 type, result_list = ld.result(msgid, 0)
         except (ldap.ADMINLIMIT_EXCEEDED, ldap.SIZELIMIT_EXCEEDED,
                 ldap.TIMELIMIT_EXCEEDED), e:
             partial = 1
         except ldap.LDAPError, e:
             raise e# ipaerror.gen_exception(ipaerror.LDAP_DATABASE_ERROR, None, e)
 
         #if not entries:
             #raise 'LDAP:NOT FOUND'# "ipaerror.gen_exception(ipaerror.LDAP_NOT_FOUND, notfound(args))
 
         if partial == 1:
             counter = -1
         else:
             counter = len(entries)
 
         return entries #[counter] + entries


	
    def adGroups(self):
	" active directory groups roles "
	res=[]
	try:
	    ld=self._open()
	    if self.GroupBase:
		dn=fl(self.GroupBase+',DC='+self.ContextName)
	    else:
		dn=fl('DC='+self.ContextName)
	    fs=fl('(objectClass=group)')
	    #print fs
	    #items=ld.search_s(dn,2,fs,['dn','sAMAccountName','description'])
	    items=self.getListAsync(ld,dn,2,fs,['dn','sAMAccountName','description'])
	    #print items
	    #ld.close()
	    for it in items:
	        it1=it[1]
	        try:
		  #print it1
	          d={}
		  d['name']=tl( it1.get('sAMAccountName',[''])[0] )
		  d['description'] = tl( it1.get('description',[''])[0] )
		  res.append(d)
		except:
		  pass
	    #print res
        except ldap.INVALID_CREDENTIALS:
	    raise "ldap INVALID_CREDENTIALS!"
	    #print name,'-not found!'
	    pass
        return res
	
    def manage_map_to_local_roles(self,roles,REQUEST=None):
	" add roles from list to the parent folder "
	parent=self.getParentNode()
	if REQUEST.has_key('add'):
	    for role in roles:
		parent._addRole(role)
	if REQUEST.has_key('delete'):
	    parent._delRoles(roles)
	    
	if REQUEST:
	  return self.manage_adGroups(REQUEST={'mapping_done':1})
	  

    def xx_validate(self, request, auth='', roles=_noroles):
	#print roles,
        self.browser=''	
	if request['HTTP_USER_AGENT'].find('MSIE')!=-1:
	    self.browser='MSIE'
        v = request['PUBLISHED'] # the published object
	return BasicUserFolder.validate(self,request,auth,roles)
	

    def xx_authorize(self, user, accessed, container, name, value, roles):
	#print user,accessed,name,roles
	return BasicUserFolder.authorize(self, user, accessed, container, name, value, roles)
	
	
	
    def xx_identify(self, auth):
        if auth and auth.lower().startswith('basic '):
	    try: 
		name, password=tuple(decodestring(auth.split(' ')[-1]).split(':', 1))
		if self.browser=='????':
		    name=_defox(name)
		    password=_defox(password)
		#print ' user ',name
	    except:								                  
		raise BadRequest, 'Invalid authentication token'
	    return name, password
	else:
	    return None, None


Globals.default__class_init__(ADUserFolder)

class ADUser (SimpleUser):
#class ADUser (User):
    """
    A simple class for user objects.
    """
    def __init__(self, name,password,roles,adroles,domains,cn,email):
#	User.__init__(self, name, password, roles, domains)
        self.id=name
        self.name = name
        self.__=password
        self._roles=roles
        self.domains=domains
	self.adroles=adroles
	self.cn=cn
	self.email=email
	
	
    def authenticate(self, password, request):
	"""try to authenticate the user"""
	if password in [None,'']:
	    return 0
	if not self.name:
	    return 0
	if pw_validate(self.__,password):
	    #print 'cashed auth!'
	    return 1
	try:
	    ld_user=ldap.open(self.domains[0])
	    ld_user.set_option(ldap.OPT_REFERRALS, 0)
	    ld_user.timelimit=10
	    #print 'try bind',fl(self.name+'@'+self.domains[1]),password
	    s=ld_user.simple_bind_s(fl(self.name+'@'+self.domains[1]),fl(password))
	    #print 'bind',s    
	    dn=fl('DC='+self.domains[1])
	    #print dn
	    fs=fl('(sAMAccountName='+self.name+')')
	    items=_clear( ld_user.search_s(dn,2,fs,['dn','sAMAccountName','memberOf']) )
	    if len(items) == 0 :
	      return 0
	    #s=ld_user.search_ext(dn,2,fs,['dn','sAMAccountName','memberOf'])
	    #items=ld_user.result(s,0)[1]
	    #print items
	    self.adroles=[]
	    roles=[]
	    try:
	      for role in items[0][1]['memberOf']:
		role=tl(role)
		r=role.split(',')[0].split('=')[1]
		if not r in ['Manager','Owner']:#Zope only roles!!
		    roles.append(r)
	      cn=items[0][0]
	      cnl=cn.split(',')
	      for cc in cnl[1:-1]:
		roles.append( tl(cc.split('=')[1]) )
	    except:
	      pass
	    self.adroles=roles
	    self.__=pw_encrypt(password, 'SSHA')
	    self.___=password
	    #print self.name,'auth success with adroles',
	    #for r in self.adroles:
		#print r,
	    return 1
	except:
	    #print self.name,'auth failire!!!'
	    return 0
	
    def getUserName(self):
        """Return the username of a user"""
        return self.name

    def _getPassword(self):
        """Return the password of the user."""
        return self.__

    def getRoles(self):
        """Return the list of roles assigned to a user."""
	#print 'getRoles',self.roles	
	roles=self.adroles+self._roles
        if self.name == 'Anonymous User': return tuple(roles)
        else: return tuple(roles) + ('Authenticated',)

    def getDomains(self):
        """Return the list of domain restrictions for a user"""
        return tuple(self.domains)

    def getProp(self, key):
        # Don't return 'private' keys
	if key[0] != '_':
	 #if hasattr(self, key):
	 #  return getattr(self, key)
	 ld_user=ldap.open(self.domains[0])
	 ld_user.set_option(ldap.OPT_REFERRALS, 0)
	 ld_user.timelimit=10
	 #print 'try bind',fl(self.name+'@'+self.domains[1]),password
         try:
	   s=ld_user.simple_bind_s(fl(self.name+'@'+self.domains[1]),self.___)
         except:
	   s=ld_user.simple_bind_s('testUser@ssgpo','userTest')

	 #s=ld_user.simple_bind_s(fl(self.name+'@'+self.domains[1]),self.getParentNode().bindPw)
	 #print 'bind',s    
	 dn=fl('DC='+self.domains[1])
	 #print dn
	 fs=fl('(sAMAccountName='+self.name+')')
	 #s=ld_user.search_ext(dn,2,fs,[key])
	 #items=ld_user.result(s,0)[1]
	 items=ld_user.search_s(dn,2,fs,[key])
	 return tl(items[0][1][key][0])
        raise KeyError, key	


	
    def __getitem__(self, key):
        # Don't return 'private' keys
	if key[0] != '_':
	 if hasattr(self, key):
	   return getattr(self, key)
	 ld_user=ldap.open(self.domains[0])
	 ld_user.set_option(ldap.OPT_REFERRALS, 0)
	 ld_user.timelimit=10
	 #print 'try bind',fl(self.name+'@'+self.domains[1]),password
	 try:
	   s=ld_user.simple_bind_s(fl(self.name+'@'+self.domains[1]),fl(password))
         except:
	   s=ld_user.simple_bind_s('testUser@ssgpo','userTest')
	 #print 'bind',s    
	 dn=fl('DC='+self.domains[1])
	 #print dn
	 fs=fl('(sAMAccountName='+self.name+')')
	 items=ld_user.search_s(dn,2,fs,[key])
	 #s=ld_user.search_ext(dn,2,fs,[key])
	 #items=ld_user.result(s,0)[1]
	 try:
	   return items[0][1][key]
	 except:
	   pass
        raise "Не найден",KeyError, key
    """																				       
    def allowed(self, object, object_roles=None):
	ret=SimpleUser.allowed(self,object,object_roles)
	#permissions=object.ac_inherited_permissions()
	n=r='-\t'
	if hasattr(object,'security'):
	    n=object.security.names
	    r=object.security.roles
	#print self.name,'allowed',ret,n,r
	return ret	
	
    def has_permission(self, permission, object):
	"Check to see if a user has a given permission on an object."
	ret=SimpleUser.has_permission(self,permission,object)
	id=getattr(object, 'id', '?')
	if callable(id): id=id()
	title=getattr(object, 'title', '?')
	if callable(title): title=title()
	#print self.name,'has perm',perm,ret,'on',id,title
	return ret
	
    def has_role(self, roles, object=None):
        "Check to see if a user has a given role or roles."
	ret=SimpleUser.has_role(self,roles,object)
	id=getattr(object, 'id', '?')
	if callable(id): id=id()
	title=getattr(object, 'title', '?')
	if callable(title): title=title()
	#print self.name,'has role',roles,ret,'on',id,title
	return ret
	    """
        
Globals.default__class_init__(ADUser)

def manage_addADUserFolder(self, dtself=None, REQUEST=None, **ignored):
    """ adding a AD User Folder"""
    f=ADUserFolder()
    self=self.this()
    try:    self._setObject('acl_users', f)
    except: return MessageDialog(
                   title  ='Item Exists',
                   message='This object already contains a User Folder',
                   action ='%s/manage_main' % REQUEST['URL1'])
    self.__allow_groups__=f
    #self.acl_users._post_init()

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect(self.absolute_url()+'/manage_main')
