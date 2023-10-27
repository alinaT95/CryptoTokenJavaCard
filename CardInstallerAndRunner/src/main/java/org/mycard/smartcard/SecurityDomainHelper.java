package org.mycard.smartcard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.mycard.common.ParseCapHelper;
import org.mycard.smartcard.pcscWrapper.ApduRunner;
import org.mycard.smartcard.pcscWrapper.RAPDU;
import org.mycard.smartcard.pcscWrapper.SecureChannel;
import org.mycard.smartcard.pcscWrapper.gp.*;
import org.mycard.smartcard.pcscWrapper.helpers.CryptoHelper;
import org.mycard.smartcard.pcscWrapper.helpers.Keys;
import org.mycard.smartcard.pcscWrapper.helpers.KeysHelper;
import org.mycard.smartcard.pcscWrapper.helpers.SessionKeys;

import java.io.File;

import static org.mycard.common.ByteArrayHelper.*;

public class SecurityDomainHelper {
    final private static Logger log = LoggerFactory.getLogger(SecurityDomainHelper.class);


    //new
    public static void installApp(ApduRunner apduRunner, boolean reinstallPackage, boolean reinstallInstance, byte[] cardManagerAid, byte[] hostChallenge, 
                                  SessionKeys sessionKeys, byte[] execLoadFileAid, byte[] execModuleAid, byte[] instanceAid, File capFile, byte[] installData,
                                  byte[] initUpdResp) throws Exception {

        log.debug("SDEK: " + hex(sessionKeys.decKey)); //3AEA282B159A7EBF401BE10C928404A0
        log.debug("SENC: " + hex(sessionKeys.encKey));
        log.debug("SMAC: " + hex(sessionKeys.macKey));


        // Verify card cryptogram
        byte[] seqCounter = bSub(initUpdResp, 12, 2);
        byte[] cardChallenge = bSub(initUpdResp, 14, 6);

        byte[] cardCrypto = bRight(initUpdResp, 8);
        byte[] cardCryptoGen = CryptoHelper.macCryptogram(
                CryptoHelper.padding(bytes(hex(hostChallenge) + hex(seqCounter) + hex(cardChallenge))),
                sessionKeys.encKey
        );

        if(!bEquals(cardCryptoGen, cardCrypto))
            throw new RuntimeException("Card cryptogram generated is not equal to cryptogram from card ("
                    + cardCryptoGen+" != "+cardCrypto+")");

        // Generate host crypto
        byte[] hostCryptoGen = CryptoHelper.macCryptogram(
                CryptoHelper.padding(bytes((hex(seqCounter) + hex(cardChallenge) + hex(hostChallenge)))),
                sessionKeys.encKey
        );

        // Create secure channel
        SecureChannel secureChannel = new SecureChannel(sessionKeys);

        /*
            EXTERNAL AUTHENTICATE
        */
        apduRunner.sendAPDU(secureChannel.addMac(
                        new ExternalAuthenticateCAPDU(hostCryptoGen, ExternalAuthenticateCAPDU.P1.CDECR_CMAC /*, secureChannel*/))
        );

        /*
            GET STATE
         */
        if(reinstallPackage)
        {
            RAPDU execs = apduRunner.sendAPDU(secureChannel.addEncMac(new GetStatusCAPDU(GetStatusCAPDU.P1.EXECS_AND_MODULES)));

            /*
                DELETE package
             */
            if(GetStatusCAPDU.isPackageInstalled(execs, execLoadFileAid))
            {
                apduRunner.sendAPDU(secureChannel.addEncMac(new DeleteCAPDU(execLoadFileAid, DeleteCAPDU.P2.OBJECT_AND_RELATED)), "Delete package");
            }

            /*
                LOAD
             */

            byte[] bytes = ParseCapHelper.read(capFile);

            apduRunner.sendAPDU(secureChannel.addEncMac(new InstallForLoadCAPDU(execLoadFileAid, cardManagerAid)));
            for (LoadCAPDU loadCAPDU : LoadCAPDU.prepareCommands(bytes)) {
                apduRunner.sendAPDU(secureChannel.addEncMac(loadCAPDU));
            }
        }

        if(reinstallInstance)
        {
            RAPDU instances = apduRunner.sendAPDU(secureChannel.addEncMac(new GetStatusCAPDU(GetStatusCAPDU.P1.APPS_AND_IS)));

            if(GetStatusCAPDU.isInstanceInstalled(instances, instanceAid))
            {
                /*
                    DELETE instance
                 */
                apduRunner.sendAPDU(secureChannel.addEncMac(new DeleteCAPDU(instanceAid, DeleteCAPDU.P2.OBJECT)), "Delete instance");
            }

            /*
                INSTALL
             */
            apduRunner.sendAPDU(secureChannel.addEncMac(new GetStatusCAPDU(GetStatusCAPDU.P1.APPS_AND_IS)));
            apduRunner.sendAPDU(secureChannel.addEncMac(new InstallForInstallCAPDU(execLoadFileAid, execModuleAid, instanceAid, installData)));
            apduRunner.sendAPDU(secureChannel.addEncMac(new GetStatusCAPDU(GetStatusCAPDU.P1.APPS_AND_IS)));

        }
    }


    //new
    public static void installApp(ApduRunner apduRunner, boolean reinstallPackage, boolean reinstallInstance,
                                  byte[] cardManagerId, byte[] hostChallenge,
                                  SessionKeys sessionKeys, byte[] execLoadFileLibAid, byte[] execLoadFileAppAid,
                                  byte[] execModuleAid, byte[] instanceAid, File capFileLib,
                                  File capFileApp, byte[] installData, byte[] initUpdResp) throws Exception {

        log.debug("SDEK: " + hex(sessionKeys.decKey)); //3AEA282B159A7EBF401BE10C928404A0
        log.debug("SENC: " + hex(sessionKeys.encKey));
        log.debug("SMAC: " + hex(sessionKeys.macKey));


        // Verify card cryptogram
        byte[] seqCounter = bSub(initUpdResp, 12, 2);
        byte[] cardChallenge = bSub(initUpdResp, 14, 6);

        byte[] cardCrypto = bRight(initUpdResp, 8);
        byte[] cardCryptoGen = CryptoHelper.macCryptogram(
                CryptoHelper.padding(bytes(hex(hostChallenge) + hex(seqCounter) + hex(cardChallenge))),
                sessionKeys.encKey
        );

        if(!bEquals(cardCryptoGen, cardCrypto))
            throw new RuntimeException("Card cryptogram generated is not equal to cryptogram from card ("
                    +cardCryptoGen+" != "+cardCrypto+")");

        // Generate host crypto
        byte[] hostCryptoGen = CryptoHelper.macCryptogram(
                CryptoHelper.padding(bytes((hex(seqCounter) + hex(cardChallenge) + hex(hostChallenge)))),
                sessionKeys.encKey
        );

        // Create secure channel
        SecureChannel secureChannel = new SecureChannel(sessionKeys);

        /*
            EXTERNAL AUTHENTICATE
        */
        apduRunner.sendAPDU(secureChannel.addMac(
                        new ExternalAuthenticateCAPDU(hostCryptoGen, ExternalAuthenticateCAPDU.P1.CDECR_CMAC /*, secureChannel*/))
        );


        // DELETE applet instance
        if(reinstallInstance) {
            RAPDU instances = apduRunner.sendAPDU(secureChannel.addEncMac(new GetStatusCAPDU(GetStatusCAPDU.P1.APPS_AND_IS)));

            if (GetStatusCAPDU.isInstanceInstalled(instances, instanceAid)) {

                apduRunner.sendAPDU(secureChannel.addEncMac(new DeleteCAPDU(instanceAid, DeleteCAPDU.P2.OBJECT)), "Delete instance");
            }
        }



        if(reinstallPackage) {

            //DELETING All packages

            RAPDU execs = apduRunner.sendAPDU(secureChannel.addEncMac(new GetStatusCAPDU(GetStatusCAPDU.P1.EXECS_AND_MODULES)));

            log.debug("AID for deleting: " + hex(execLoadFileAppAid));

            if (GetStatusCAPDU.isPackageInstalled(execs, execLoadFileAppAid)) {
                apduRunner.sendAPDU(secureChannel.addEncMac(new DeleteCAPDU(execLoadFileAppAid, DeleteCAPDU.P2.OBJECT_AND_RELATED)), "Delete package");
            }

            log.debug("AID for deleting: " + hex(execLoadFileLibAid));

            if (GetStatusCAPDU.isPackageInstalled(execs, execLoadFileLibAid)) {
                apduRunner.sendAPDU(secureChannel.addEncMac(new DeleteCAPDU(execLoadFileLibAid, DeleteCAPDU.P2.OBJECT_AND_RELATED)), "Delete package");
            }

            //LOAD All packages

            byte[] bytes = ParseCapHelper.read(capFileLib);

            apduRunner.sendAPDU(secureChannel.addEncMac(new InstallForLoadCAPDU(execLoadFileLibAid, cardManagerId)));
            for (LoadCAPDU loadCAPDU : LoadCAPDU.prepareCommands(bytes)) {
                apduRunner.sendAPDU(secureChannel.addEncMac(loadCAPDU));
            }


            bytes = ParseCapHelper.read(capFileApp);

            apduRunner.sendAPDU(secureChannel.addEncMac(new InstallForLoadCAPDU(execLoadFileAppAid, cardManagerId)));
            for (LoadCAPDU loadCAPDU : LoadCAPDU.prepareCommands(bytes)) {
                apduRunner.sendAPDU(secureChannel.addEncMac(loadCAPDU));
            }

        }

        // CREATE applet instance
        if(reinstallInstance)
        {
            RAPDU instances = apduRunner.sendAPDU(secureChannel.addEncMac(new GetStatusCAPDU(GetStatusCAPDU.P1.APPS_AND_IS)));

            /*
                INSTALL
             */
            apduRunner.sendAPDU(secureChannel.addEncMac(new GetStatusCAPDU(GetStatusCAPDU.P1.APPS_AND_IS)));
            apduRunner.sendAPDU(secureChannel.addEncMac(new InstallForInstallCAPDU(execLoadFileAppAid, execModuleAid, instanceAid, installData)));
            apduRunner.sendAPDU(secureChannel.addEncMac(new GetStatusCAPDU(GetStatusCAPDU.P1.APPS_AND_IS)));

        }
    }



    //new
    public static void deleteApp(ApduRunner apduRunner, boolean deletePackage, byte[] cardManagerId, byte[] hostChallenge, SessionKeys sessionKeys,
                                 byte[] execLoadFileAid, byte[] instanceAid, byte[] initUpdResp) throws Exception {

        log.debug("SDEK: " + hex(sessionKeys.decKey)); //3AEA282B159A7EBF401BE10C928404A0
        log.debug("SENC: " + hex(sessionKeys.encKey));
        log.debug("SMAC: " + hex(sessionKeys.macKey));

        // Verify card cryptogram
        byte[] seqCounter = bSub(initUpdResp, 12, 2);
        byte[] cardChallenge = bSub(initUpdResp, 14, 6);

        byte[] cardCrypto = bRight(initUpdResp, 8);
        byte[] cardCryptoGen = CryptoHelper.macCryptogram(
                CryptoHelper.padding(bytes(hex(hostChallenge) + hex(seqCounter) + hex(cardChallenge))),
                sessionKeys.encKey
        );

        if(!bEquals(cardCryptoGen, cardCrypto))
            throw new RuntimeException("Card cryptogram generated is not equal to cryptogram from card ("
                    +cardCryptoGen+" != "+cardCrypto+")");

        // Generate host crypto
        byte[] hostCryptoGen = CryptoHelper.macCryptogram(
                CryptoHelper.padding(bytes((hex(seqCounter) + hex(cardChallenge) + hex(hostChallenge)))),
                sessionKeys.encKey
        );

        // Create secure channel
        SecureChannel secureChannel = new SecureChannel(sessionKeys);

        /*
            EXTERNAL AUTHENTICATE
        */
        apduRunner.sendAPDU(secureChannel.addMac(
                        new ExternalAuthenticateCAPDU(hostCryptoGen, ExternalAuthenticateCAPDU.P1.CDECR_CMAC/*, secureChannel*/))
        );

        if(deletePackage) {

            log.debug("Aid for deletion (Load file): "+hex(execLoadFileAid));
            RAPDU execs = apduRunner.sendAPDU(secureChannel.addEncMac(new GetStatusCAPDU(GetStatusCAPDU.P1.EXECS_AND_MODULES)));

            //DELETE package and instance
            if (GetStatusCAPDU.isPackageInstalled(execs, execLoadFileAid)) {
                apduRunner.sendAPDU(secureChannel.addEncMac(new DeleteCAPDU(execLoadFileAid, DeleteCAPDU.P2.OBJECT_AND_RELATED)), "Delete package and instance");
            }
        }
        else {
            log.debug("Aid for deletion (Instance file): "+hex(instanceAid));

            RAPDU instances = apduRunner.sendAPDU(secureChannel.addEncMac(new GetStatusCAPDU(GetStatusCAPDU.P1.APPS_AND_IS)));
            if(GetStatusCAPDU.isInstanceInstalled(instances, instanceAid))
            {
                //DELETE instance
                apduRunner.sendAPDU(secureChannel.addEncMac(new DeleteCAPDU(instanceAid, DeleteCAPDU.P2.OBJECT)), "Delete instance");
            }

            //DELETE instance
            apduRunner.sendAPDU(secureChannel.addEncMac(new DeleteCAPDU(instanceAid, DeleteCAPDU.P2.OBJECT)), "Delete instance only");
        }


    }



//   /// OLD
   public static void installApp(ApduRunner apduRunner, boolean reinstallPackage, boolean reinstallInstance, byte[] cardManagerId, byte[] hostChallenge,
                                 Keys ISDKeys, byte[] execLoadFileAid, byte[] execModuleAid, byte[] instanceAid, File capFile, byte[] installData) throws Exception {


    apduRunner.sendAPDU(new SelectAidCAPDU(cardManagerId), "Select Card Manager");


    RAPDU initUpdResp = apduRunner.sendAPDU(new InitializeUpdateCAPDU(hostChallenge));

    // Derive session keys
    SessionKeys sessionKeys = KeysHelper.deriveSessionKeys(ISDKeys, hex(initUpdResp.getData()));

    log.debug("SDEK: " + hex(sessionKeys.decKey)); //3AEA282B159A7EBF401BE10C928404A0
    log.debug("SENC: " + hex(sessionKeys.encKey));
    log.debug("SMAC: " + hex(sessionKeys.macKey));


    // Verify card cryptogram
    byte[] seqCounter = bSub(initUpdResp.getData(), 12, 2);
    byte[] cardChallenge = bSub(initUpdResp.getData(), 14, 6);

    byte[] cardCrypto = bRight(initUpdResp.getData(), 8);
    byte[] cardCryptoGen = CryptoHelper.macCryptogram(
            CryptoHelper.padding(bytes(hex(hostChallenge) + hex(seqCounter) + hex(cardChallenge))),
            sessionKeys.encKey
    );

    if(!bEquals(cardCryptoGen, cardCrypto))
            throw new RuntimeException("Card cryptogram generated is not equal to cryptogram from card ("
                                               +cardCryptoGen+" != "+cardCrypto+")");

    // Generate host crypto
    byte[] hostCryptoGen = CryptoHelper.macCryptogram(
            CryptoHelper.padding(bytes((hex(seqCounter) + hex(cardChallenge) + hex(hostChallenge)))),
            sessionKeys.encKey
    );

    // Create secure channel
    SecureChannel secureChannel = new SecureChannel(sessionKeys);


    apduRunner.sendAPDU(secureChannel.addMac(
            new ExternalAuthenticateCAPDU(hostCryptoGen, ExternalAuthenticateCAPDU.P1.CDECR_CMAC /*, secureChannel*/))
            );


    if(reinstallPackage)
    {
        RAPDU execs = apduRunner.sendAPDU(secureChannel.addEncMac(new GetStatusCAPDU(GetStatusCAPDU.P1.EXECS_AND_MODULES)));


        if(GetStatusCAPDU.isPackageInstalled(execs, execLoadFileAid))
        {
            apduRunner.sendAPDU(secureChannel.addEncMac(new DeleteCAPDU(execLoadFileAid, DeleteCAPDU.P2.OBJECT_AND_RELATED)), "Delete package");
        }



        byte[] bytes = ParseCapHelper.read(capFile);

        apduRunner.sendAPDU(secureChannel.addEncMac(new InstallForLoadCAPDU(execLoadFileAid, cardManagerId)));
        for (LoadCAPDU loadCAPDU : LoadCAPDU.prepareCommands(bytes)) {
            apduRunner.sendAPDU(secureChannel.addEncMac(loadCAPDU));
        }
    }

    if(reinstallInstance)
    {
        RAPDU instances = apduRunner.sendAPDU(secureChannel.addEncMac(new GetStatusCAPDU(GetStatusCAPDU.P1.APPS_AND_IS)));

        if(GetStatusCAPDU.isInstanceInstalled(instances, instanceAid))
        {

            apduRunner.sendAPDU(secureChannel.addEncMac(new DeleteCAPDU(instanceAid, DeleteCAPDU.P2.OBJECT)), "Delete instance");
        }


        apduRunner.sendAPDU(secureChannel.addEncMac(new GetStatusCAPDU(GetStatusCAPDU.P1.APPS_AND_IS)));
        apduRunner.sendAPDU(secureChannel.addEncMac(new InstallForInstallCAPDU(execLoadFileAid, execModuleAid, instanceAid, installData)));
        apduRunner.sendAPDU(secureChannel.addEncMac(new GetStatusCAPDU(GetStatusCAPDU.P1.APPS_AND_IS)));

    }
}



//  //OLD
   public static void deleteApp(ApduRunner apduRunner, boolean deletePackage, byte[] cardManagerId, byte[] hostChallenge,
                                Keys ISDKeys, byte[] execLoadFileAid, byte[] instanceAid) throws Exception {


        apduRunner.sendAPDU(new SelectAidCAPDU(cardManagerId), "Select Card Manager");


        RAPDU initUpdResp = apduRunner.sendAPDU(new InitializeUpdateCAPDU(hostChallenge));

        // Derive session keys
        SessionKeys sessionKeys = KeysHelper.deriveSessionKeys(ISDKeys, hex(initUpdResp.getData()));

        log.debug("SDEK: " + hex(sessionKeys.decKey)); //3AEA282B159A7EBF401BE10C928404A0
        log.debug("SENC: " + hex(sessionKeys.encKey));
        log.debug("SMAC: " + hex(sessionKeys.macKey));


        // Verify card cryptogram
        byte[] seqCounter = bSub(initUpdResp.getData(), 12, 2);
        byte[] cardChallenge = bSub(initUpdResp.getData(), 14, 6);

        byte[] cardCrypto = bRight(initUpdResp.getData(), 8);
        byte[] cardCryptoGen = CryptoHelper.macCryptogram(
                CryptoHelper.padding(bytes(hex(hostChallenge) + hex(seqCounter) + hex(cardChallenge))),
                sessionKeys.encKey
        );

        if(!bEquals(cardCryptoGen, cardCrypto))
            throw new RuntimeException("Card cryptogram generated is not equal to cryptogram from card ("
                    +cardCryptoGen+" != "+cardCrypto+")");

        // Generate host crypto
        byte[] hostCryptoGen = CryptoHelper.macCryptogram(
                CryptoHelper.padding(bytes((hex(seqCounter) + hex(cardChallenge) + hex(hostChallenge)))),
                sessionKeys.encKey
        );

        // Create secure channel
        SecureChannel secureChannel = new SecureChannel(sessionKeys);


        apduRunner.sendAPDU(secureChannel.addMac(
                        new ExternalAuthenticateCAPDU(hostCryptoGen, ExternalAuthenticateCAPDU.P1.CDECR_CMAC/*, secureChannel*/))
        );

        if(deletePackage) {
            RAPDU execs = apduRunner.sendAPDU(secureChannel.addEncMac(new GetStatusCAPDU(GetStatusCAPDU.P1.EXECS_AND_MODULES)));

            //DELETE package and instance
            if (GetStatusCAPDU.isPackageInstalled(execs, execLoadFileAid)) {
                apduRunner.sendAPDU(secureChannel.addEncMac(new DeleteCAPDU(execLoadFileAid, DeleteCAPDU.P2.OBJECT_AND_RELATED)), "Delete package and instance");
            }
        }
        else {

            RAPDU instances = apduRunner.sendAPDU(secureChannel.addEncMac(new GetStatusCAPDU(GetStatusCAPDU.P1.APPS_AND_IS)));
            if(GetStatusCAPDU.isInstanceInstalled(instances, instanceAid))
            {
                //DELETE instance
                apduRunner.sendAPDU(secureChannel.addEncMac(new DeleteCAPDU(instanceAid, DeleteCAPDU.P2.OBJECT)), "Delete instance");
            }

            //DELETE instance
            apduRunner.sendAPDU(secureChannel.addEncMac(new DeleteCAPDU(instanceAid, DeleteCAPDU.P2.OBJECT)), "Delete instance only");
        }


    }

}
