"""
SNMP TRAP and Infor Reciver for SNMP V1,V2c,V3
"""

import argparse

try:
    from pysnmp.entity import engine, config
    from pysnmp.carrier.asyncore.dgram import udp, udp6
    from pysnmp.entity.rfc3413 import ntfrcv
    from pysnmp.proto.api import v2c
    from pysnmp.smi import builder, view, compiler, rfc1902, error
    from pysnmp import debug
except ImportError:
    print "IMPORT ERROR Please install PYSNMP 4.3.8 usning"

mibViewController = None
pdu_count = 1

def user_input(snmpEngine):
    """
    TBD
    :param snmpEngine:
    :return:
    """
    CUSTOM_MIB_PATH= '/usr/share/snmp/mibs/'
    LOAD_MIB_MODULE = ''
    ans = 'no'
    print "\n"
    PORT=raw_input("Please Provide The SNMP Trap Port: ")
    print "\n"
    vserion = raw_input("Please Enter SNMP Version [OPTION: 1,2,3] :")
    print "\n"
    ip_type = raw_input("Please IP Type [OPTION: 4, 6] :")
    print "\n"
    if vserion in ['1', '2']:
        COMMUNITYSTRING = raw_input("Please Provide SNMP V1/V2 community "
                                  "String: ")
        print "\n"
        config.addV1System(snmpEngine, COMMUNITYSTRING, COMMUNITYSTRING)
        while 1:
            asn = raw_input("Waant to add a another community ("
                                        "Yes/No/n/y)?")
            if ans in ["yes", "Yes", "Y", "y"]:
                COMMUNITYSTRING = raw_input(
                    "Please Provide SNMP V1/V2 community "
                    "String: ")
                config.addV1System(snmpEngine, COMMUNITYSTRING, COMMUNITYSTRING)
            else:
                break
    else:
        add_snmp_v3(snmpEngine)
    print "\n"
    _new_mib_path=raw_input("Please provide the custom mib dir path: ")
    print "\n"
    _new_mib_path = _new_mib_path.strip()
    if _new_mib_path and _new_mib_path[-1] == "/":
        CUSTOM_MIB_PATH = _new_mib_path+','+CUSTOM_MIB_PATH
    else:
        CUSTOM_MIB_PATH = _new_mib_path+'/'+','+CUSTOM_MIB_PATH
    LOAD_MIB_MODULE = raw_input("Please provide the custom MIB Name seperated "
                              "by comma: ")
    print "\n"
    return COMMUNITYSTRING, CUSTOM_MIB_PATH, PORT, LOAD_MIB_MODULE, ip_type


def add_transport(snmpEngine, PORT, ip_type):
    """
    :param snmpEngine:
    :return:
    """
    try:

        if ip_type == '6':
            config.addTransport(
                             snmpEngine,
                             udp.domainName,
                             udp6.Udp6SocketTransport().openServerMode((
                                 '::', int(PORT)))
                            )
        else:
            config.addTransport(
                             snmpEngine,
                             udp.domainName,
                             udp.UdpTransport().openServerMode(('0.0.0.0',
                                                           int(PORT)))
                            )
    except Exception as e:
        print "{} Port Binding Failed the Provided Port {} is in Use".format(e, PORT)



def add_snmp_v3(snmpEngine):
    """
    TBD
    :param snmpEngine:
    :return:
    """
    __authProtocol = {
        'usmHMACMD5AuthProtocol': config.usmHMACMD5AuthProtocol,
        'usmHMACSHAAuthProtocol': config.usmHMACSHAAuthProtocol,
        'usmAesCfb128Protocol': config.usmAesCfb128Protocol,
        'usmAesCfb256Protocol': config.usmAesCfb256Protocol,
        'usmAesCfb192Protocol': config.usmAesCfb192Protocol,
        'usmDESPrivProtocol': config.usmDESPrivProtocol,
        'usmNoAuthProtocol': config.usmNoAuthProtocol,
        'usmNoPrivProtocol': config.usmNoPrivProtocol
    }
    while 1:
         V3=raw_input("Want to add New V3 User (Yes/No/n/y)?")
         if V3 in ["yes", "Yes", "Y", "y"]:
             v3_user = raw_input("Provide V3 User Name: ")
             print "\n"
             v3_authkey = raw_input("Provide Auth Key: ")
             print "\n"
             v3_privkey = raw_input("Provide Priv Key: ")
             print "\n"
             authProtocol = raw_input("Provide authProtocol: Option: ["
                                      "usmNoAuthProtocol, "
                                      "usmHMACMD5AuthProtocol, "
                                      "usmHMACSHAAuthProtocol] :")
             print "\n"
             privProtocol = raw_input("Provide privProtocol: Option: ["
                                      "usmNoPrivProtocol, usmDESPrivProtocol, usm3DESEDEPrivProtocol, usmAesCfb128Protocol] :")
             print "\n"
             securityEngineId = raw_input("Provide V3 security EngineId e.g. "
                                          "'800000d30300000e112245' :")
             print "\n"
             config.addV3User(
                             snmpEngine, userName=v3_user,
                                  authKey=v3_authkey, privKey=v3_privkey,
                                  authProtocol=__authProtocol.get(
                                      authProtocol, config.usmNoAuthProtocol),
                                  privProtocol=__authProtocol.get(
                                      privProtocol,config.usmNoPrivProtocol),
                                  securityEngineId=v2c.OctetString(
                                  hexValue=securityEngineId))
         elif V3 in ["No", "n", "N", "no"]:
             break
         else:
             continue

def mib_builder(custom_mib_path, LOAD_MIB_MODULE):
    mibBuilder = builder.MibBuilder()
    try:
        if custom_mib_path:
            compiler.addMibCompiler(mibBuilder, sources=custom_mib_path.split(
              ","))
        global mibViewController
        mibViewController = view.MibViewController(mibBuilder)
        if LOAD_MIB_MODULE:
            _mibs=LOAD_MIB_MODULE.split(",")
            mibBuilder.loadModules(*_mibs)
    except error.MibNotFoundError as excep:
        print " {} Mib Not Found!".format(excep)


def cbFun(snmpEngine, stateReference, contextEngineId, contextName,
          varBinds, cbCtx):
    global pdu_count
    global mibViewController
    print "####################### NEW Notification(PDU_COUNT: {}) #######################".format(pdu_count)
    execContext = snmpEngine.observer.getExecutionContext(
        'rfc3412.receiveMessage:request'
    )
    print('#Notification from %s \n#ContextEngineId: "%s" \n#ContextName: "%s" \n#SNMPVER "%s" \n#SecurityName "%s"' % ('@'.join([str(x) for x in execContext['transportAddress']]),contextEngineId.prettyPrint(),contextName.prettyPrint(), execContext['securityModel'], execContext['securityName']))
    for oid, val in varBinds:
        output = rfc1902.ObjectType(rfc1902.ObjectIdentity(oid),val).resolveWithMib(mibViewController).prettyPrint()
        print output
    pdu_count +=1


def check_parser():
    """
    TBD
    :return:
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug",
                        help="Enable Debug Mode")
    args = parser.parse_args()
    if args.debug:
        debug.setLogger(debug.Debug('all'))


if __name__ == "__main__":
    check_parser()

    snmpEngine = engine.SnmpEngine()
    COMMUNITYSTRING, CUSTOM_MIB_PATH, PORT, LOAD_MIB_MODULE, ip_type = user_input(
        snmpEngine)
    ntfrcv.NotificationReceiver(snmpEngine, cbFun)
    add_transport(snmpEngine, PORT, ip_type)
    snmpEngine.transportDispatcher.jobStarted(1)
    try:
        print "Trap Listener started ....."
        print "To Stop Press Ctrl+c"
        print "\n"
        snmpEngine.transportDispatcher.runDispatcher()
    except:
        snmpEngine.transportDispatcher.closeDispatcher()
        raise