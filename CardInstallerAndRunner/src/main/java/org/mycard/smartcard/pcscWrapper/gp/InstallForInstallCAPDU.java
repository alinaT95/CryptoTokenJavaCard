package org.mycard.smartcard.pcscWrapper.gp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.mycard.common.ByteArrayHelper.bConcat;

public class InstallForInstallCAPDU extends InstallCAPDU {
    final private static Logger log = LoggerFactory.getLogger(InstallForInstallCAPDU.class);


    public InstallForInstallCAPDU(byte[] execLoadFileAid, byte[] execModuleAid, byte[] aid, byte[] installData) throws Exception {
        super(P1.MAKE_INSTALL_AND_SELECTABLE, bConcat(
                new byte[]{(byte) execLoadFileAid.length},
                execLoadFileAid,
                new byte[]{(byte) execModuleAid.length},
                execModuleAid,
                new byte[]{(byte) aid.length},
                aid,
                new byte[]{1}, // length of app priveleges //todo: hardcode
                new byte[]{0x00}, // app priveleges //todo: hardcode
                new byte[]{(byte) (2 + installData.length)}, // length of install params //todo: hardcode
                new byte[]{(byte) 0xC9, (byte) installData.length}, // install params //todo: hardcode, what this params mean?
                installData,
                new byte[]{0x00} // length of install tocken //todo: hardcode
        ));
    }




    @Override
    public String getDescr() {
        return "Install [for install]";
    }


}


