package org.mycard.smartcard.pcscWrapper.gp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.mycard.common.ByteArrayHelper.bConcat;


public class InstallForLoadCAPDU extends InstallCAPDU {
    final private static Logger log = LoggerFactory.getLogger(InstallForLoadCAPDU.class);


    public InstallForLoadCAPDU(byte[] loadFileAid, byte[] sdAid) throws Exception {
        super(P1.MAKE_LOAD, bConcat(
                new byte[]{(byte) loadFileAid.length},
                loadFileAid,
                new byte[]{(byte) sdAid.length},
                sdAid,
                new byte[]{(byte) 0}, //Length of Load File Data Block Hash
                new byte[]{(byte) 0}, //Length of load parameters field
                new byte[]{(byte) 0} //Length of Load Token
        ));
    }




    @Override
    public String getDescr() {
        return "Install [for load]";
    }


}


