package org.mycard.smartcard.pcscWrapper.gp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.mycard.smartcard.pcscWrapper.CAPDU;
import org.mycard.smartcard.pcscWrapper.RAPDU;

import java.util.*;

import static org.mycard.common.ByteArrayHelper.*;


public class GetStatusCAPDU extends CAPDU {
    final private static Logger log = LoggerFactory.getLogger(GetStatusCAPDU.class);


    public static enum P1 {
        ISD(0x80),
        APPS_AND_IS(0x40),
        EXECS(0x20),
        EXECS_AND_MODULES(0x10)
        ;
        private final byte value;

        P1(int value) {
            this.value = (byte) value;
        }
    }

    private P1 p1;

    public GetStatusCAPDU(P1 p1) throws Exception {
        super(0x80, 0xF2, p1.value, 0x00, bytes("4F00"));
        this.p1 = p1;
    }


    @Override
    public String getDescr() {
        return "Get status (" + p1.name() + ")";
    }

    @Override
    public List<byte[]> getSuccessResults() {
        List<byte[]> result = new ArrayList<>(super.getSuccessResults());
        result.add(new byte[]{0x6A, (byte) 0x88}); //this is result when there are not installed apps
        return result;
    }

    private static final byte STATE_LOADED = 0x1;
    private static final byte STATE_SELECTABLE = 0x7;
    private static final byte STATE_INSTALLED = 0x3;
    private static final byte STATE_LOCKED = (byte) 0x83;

    @Override
    public void printMore(RAPDU rapdu) {
        System.out.println("");
        switch (p1)
        {
            case ISD:
            case APPS_AND_IS:
            case EXECS:
            {

                Set<String> installed = getInstalledInstances(rapdu);

                for (String aid : installed) {
                    System.out.println("AID: " + aid+ " ("+new String(bytes(aid))+")");
                }
                break;
            }

            case EXECS_AND_MODULES:
            {
                Map<String, List<String>> installed = getLoadedExecsAndModules(rapdu);

                for (Map.Entry<String, List<String>> listEntry : installed.entrySet()) {
                    System.out.println("Executable Load File AID: " + listEntry.getKey() + " ("+new String(bytes(listEntry.getKey()))+")");
                    for (String module : listEntry.getValue()) {
                        System.out.println("    Executable Module AID: " + module + " ("+new String(bytes(module))+")");
                    }
                }
                break;
            }
        }
    }

    private static Set<String> getInstalledInstances(RAPDU rapdu) {
        Set<String> installed = new HashSet<>();

        byte[] applets = rapdu.getData();
        while (applets.length>0)
        {
            byte len = applets[0]; applets = bRight(applets, applets.length - 1);
            byte[] aid = bLeft(applets, len); applets = bRight(applets, applets.length - len);
            byte[] state = bLeft(applets, 1); applets = bRight(applets, applets.length - 1);
            byte[] privs = bLeft(applets, 1); applets = bRight(applets, applets.length - 1);

            byte stateB = state[0];
            String stateDesc =
                    (stateB | STATE_LOADED) == STATE_LOADED ? "LOADED"
                            : (stateB | STATE_SELECTABLE) == STATE_SELECTABLE ? "SELECTABLE"
                            : (stateB | STATE_INSTALLED) == STATE_INSTALLED ? "INSTALLED"
                            : (stateB | STATE_LOCKED) == STATE_LOCKED ? "LOCKED"
                            : "unknown";

            installed.add(hex(aid));

        }
        return installed;
    }

    private static Map<String, List<String>> getLoadedExecsAndModules(RAPDU rapdu) {
        Map<String, List<String>> installed = new HashMap<>();
        byte[] applets = rapdu.getData();
        while (applets.length>0)
        {
            byte len = applets[0]; applets = bRight(applets, applets.length - 1);
            byte[] aid = bLeft(applets, len); applets = bRight(applets, applets.length - len);
            byte[] state = bLeft(applets, 1); applets = bRight(applets, applets.length - 1);
            byte[] privs = bLeft(applets, 1); applets = bRight(applets, applets.length - 1);
            byte[] modNum = bLeft(applets, 1); applets = bRight(applets, applets.length - 1);

            byte stateB = state[0];
            String stateDesc =
                    (stateB | STATE_LOADED) == STATE_LOADED ? "LOADED"
                            : (stateB | STATE_SELECTABLE) == STATE_SELECTABLE ? "SELECTABLE"
                            : (stateB | STATE_INSTALLED) == STATE_INSTALLED ? "INSTALLED"
                            : (stateB | STATE_LOCKED) == STATE_LOCKED ? "LOCKED"
                            : "unknown";

            List<String> modules = new ArrayList<>();
            for (int i = 0; i < modNum[0]; i++) {
                byte modLen = applets[0]; applets = bRight(applets, applets.length - 1);
                byte[] modAid = bLeft(applets, modLen); applets = bRight(applets, applets.length - modLen);
                modules.add(hex(modAid));
            }

            installed.put(hex(aid), modules);

        }
        return installed;
    }


    public static boolean isPackageInstalled(RAPDU response, byte[] aid)
    {
        Map<String, List<String>> execToModulesMap = getLoadedExecsAndModules(response);
        return execToModulesMap.containsKey(hex(aid));
    }

    public static boolean isInstanceInstalled(RAPDU response, byte[] aid)
    {
        return getInstalledInstances(response).contains(hex(aid));
    }
}


