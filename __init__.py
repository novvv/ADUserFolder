import ADUserFolder

# CMF Prop source needs things we might not have
# So we wrap the import
try:
	import cmfPropSource
except:
	pass

try:
    from Products.CMFCore.DirectoryView import registerDirectory
    import GroupsToolPermissions
except:
    # No registerdir available -> we ignore
    pass

def initialize(context):
    try:
        registerDirectory('skins', gearuserfolder_globals)
    except:
        pass

    context.registerClass(ADUserFolder.ADUserFolder,
			  meta_type="Active Directory User Folder",
			  permission="Add User Folders",
			  constructors=(ADUserFolder.manage_addADUserFolder,),
			  icon="www/ADUserFolder.gif")