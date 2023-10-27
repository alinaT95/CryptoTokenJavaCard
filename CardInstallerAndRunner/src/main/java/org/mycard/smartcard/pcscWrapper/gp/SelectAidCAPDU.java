package org.mycard.smartcard.pcscWrapper.gp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.mycard.common.TLV;
import org.mycard.smartcard.pcscWrapper.CAPDU;
import org.mycard.smartcard.pcscWrapper.RAPDU;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.mycard.common.ByteArrayHelper.bytes;


public class SelectAidCAPDU extends CAPDU {
    final private static Logger log = LoggerFactory.getLogger(SelectAidCAPDU.class);

    public SelectAidCAPDU(byte[] aid)
    {
        super(0x00, 0xA4, 0x04, 0x00, aid);
    }


    @Override
    public String getDescr() {
        return "Select AID";
    }




    public static Set<String> isList = new HashSet<>();
    public static Map<String, String> tagInfo = new HashMap<>();



    /*
        Information about some standard GP tags
     */

    static {
        isList.add("6F");
        isList.add("6F-A5");
        isList.add("6F-A5-73");
        isList.add("6F-A5-73-60");
        isList.add("6F-A5-73-63");
        isList.add("6F-A5-73-64");
    }

    static {
        tagInfo.put("6F", "File Control Information (FCI template)");
        tagInfo.put("6F-84", "Application / file AID");
        tagInfo.put("6F-A5", "Proprietary data");
        tagInfo.put("6F-A5-9F6E", "Application production life cycle data (Optional)");
        tagInfo.put("6F-A5-9F65", "Maximum length of data field in command message (Mandatory)");
        tagInfo.put("6F-A5-73", "Security Domain Management Data (see Appendix F for detailed coding)");

        tagInfo.put("6F-A5-73-06", "Universal tag for “Object Identifier”");
        tagInfo.put("6F-A5-73-66", "Card / chip details");
        tagInfo.put("6F-A5-73-65", "Card configuration details");

        tagInfo.put("6F-A5-73-60", "{globalPlatform 2 v}");
        tagInfo.put("6F-A5-73-60-06", "OID for Card Management Type and Version");
        tagInfo.put("6F-A5-73-63", "{globalPlatform 3 v}");
        tagInfo.put("6F-A5-73-63-06", "OID for Card Identification Scheme");
        tagInfo.put("6F-A5-73-64", "{globalPlatform 4 spc i}");
        tagInfo.put("6F-A5-73-64-06", "OID for Secure Channel Protocol of " +
                "the selected Security Domain and its " +
                "implementation options");

    }

    @Override
    public void printMore(RAPDU rapdu) {
        printTLV(TLV.parseMap(rapdu.getData()));
    }

    public static void printTLV(Map<String, String> tlv) {
        printTLV(tlv, 0, "");
    }

    public static void printTLV(Map<String, String> tlv, int level, String parent) {
        for (Map.Entry<String, String> entry : tlv.entrySet()) {
            String fullTagName = parent.equals("") ? entry.getKey() : parent + "-" + entry.getKey();

            StringBuilder msg = new StringBuilder();
            for (int i = 0; i < level*4; i++) {
                msg.append(" ");
            }
            msg.append(entry.getKey());

            if(isList.contains(fullTagName))
            {
                if(tagInfo.containsKey(fullTagName))
                {
                    msg.append(" - ");
                    msg.append(tagInfo.get(fullTagName));
                }
                log.debug(msg.toString());
                printTLV(TLV.parseMap(bytes(entry.getValue())), level+1, fullTagName);
            }
            else {
                msg.append(" | ");
                msg.append(entry.getValue());
                if(tagInfo.containsKey(fullTagName))
                {
                    msg.append(" - ");
                    msg.append(tagInfo.get(fullTagName));
                }
                log.debug(msg.toString());
            }
        }
    }

}
