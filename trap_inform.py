from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto.api import v2c
from pysnmp.smi import builder, view, compiler, rfc1902, error
from pysnmp import debug 
#debug.setLogger(debug.Debug('all'))

custom_mib_path= '/usr/share/snmp/mibs/'
load_mib_module = 'SNMPv2-MIB,SNMP-COMMUNITY-MIB,FSS-COMMON-TC,FSS-COMMON-LOG,FNC-COMMON-SMI,FNCNMS'
print "\n"
PORT=raw_input("Please Provide The SNMP Trap Port: ")
print "\n"
COMMUNITYSTRING = raw_input("Please Provide SNMP V1/V2 community String: ")
print "\n"
_new_mib_path=raw_input("Please provide the custom mib dir path: ")
print "\n"
_new_mib_path = _new_mib_path.strip()
if _new_mib_path[-1] == "/":
    custom_mib_path = _new_mib_path+','+custom_mib_path
else:
    custom_mib_path = _new_mib_path+'/'+','+custom_mib_path




snmpEngine = engine.SnmpEngine()
config.addV1System(snmpEngine, COMMUNITYSTRING, COMMUNITYSTRING)
#config.addV1System(snmpEngine, "testing3", "testing3")
#config.addV1System(snmpEngine, "testing4", "testing4")
#config.addV1System(snmpEngine, "testing5", "testing5")
#config.addV1System(snmpEngine, "testing2", "testing2")
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpTransport().openServerMode(('0.0.0.0', int(PORT)))
)

# while 1:
    # V3=raw_input("Want to add V3 User (Yes/No/n/y)?")
    # if V3 in ["yes", "Yes", "Y", "y"]:
        # v3_user = raw_input("Provide V3 User Name: ")
        # v3_authkey = raw_input("Provide Auth Key: ")
        # v3_privkey = raw_input("Provide Priv Key: ")
        # v3_
    # elif V3 in ["No", "n", "N", "no"]:
        # break
    # else:
        # continue



config.addV3User(
    snmpEngine, 'authprivusr1',
    config.usmHMACMD5AuthProtocol, 'admin123',
    config.usmAesCfb128Protocol, 'admin123',
    securityEngineId=v2c.OctetString(hexValue='800000d30300000e112245')
)

#config.addV3User(
#    snmpEngine, 'authprivusr2',
#    config.usmHMACMD5AuthProtocol, 'admin123',
#    config.usmDESPrivProtocol, 'admin123',
#    securityEngineId=v2c.OctetString(hexValue='800000d30300000e112245')
#)

#config.addV3User(
#    snmpEngine, 'authprivusr3',
#    config.usmHMACSHAAuthProtocol, 'admin123',
#    config.usmNoPrivProtocol, None,
#    securityEngineId=v2c.OctetString(hexValue='800000d30300000e112245')
#)

#config.addV3User(
#    snmpEngine, 'authprivusr4',
#    config.usmNoAuthProtocol, None,
#    config.usmNoPrivProtocol, None,
#    securityEngineId=v2c.OctetString(hexValue='800000d30300000e112245')
#)

#config.addV3User(
#    snmpEngine, 'authprivusr5',
#    config.usmHMACSHAAuthProtocol, 'admin123',
#    config.usmAesCfb128Protocol, 'admin123',
#    securityEngineId=v2c.OctetString(hexValue='800000d30300000e112245')
#)


mibBuilder = builder.MibBuilder()

compiler.addMibCompiler(mibBuilder, sources=custom_mib_path.split(","))
mibViewController = view.MibViewController(mibBuilder)


for mibs in load_mib_module.split(","):
    mibBuilder.loadModules(mibs)
    
pdu_count = 1
def cbFun(snmpEngine, stateReference, contextEngineId, contextName,
          varBinds, cbCtx):
    global pdu_count
    print "####################### NEW Notification(PDU_COUNT: {}) #######################".format(pdu_count)
    execContext = snmpEngine.observer.getExecutionContext(
        'rfc3412.receiveMessage:request'
    )
    #print "########### execContext {}".format(execContext) 
    print('#Notification from %s \n#ContextEngineId: "%s" \n#ContextName: "%s" \n#SNMPVER "%s" \n#SecurityName "%s"' % ('@'.join([str(x) for x in execContext['transportAddress']]),contextEngineId.prettyPrint(),contextName.prettyPrint(), execContext['securityModel'], execContext['securityName']))
    for oid, val in varBinds:
        output = rfc1902.ObjectType(rfc1902.ObjectIdentity(oid),val).resolveWithMib(mibViewController).prettyPrint()
        print output
    pdu_count +=1

ntfrcv.NotificationReceiver(snmpEngine, cbFun)
snmpEngine.transportDispatcher.jobStarted(1) 
try:
    print "Trap Listener started ....."
    print "To Stop Press Ctrl+c"
    print "\n"
    snmpEngine.transportDispatcher.runDispatcher()
except:
    snmpEngine.transportDispatcher.closeDispatcher()
    raise
    
