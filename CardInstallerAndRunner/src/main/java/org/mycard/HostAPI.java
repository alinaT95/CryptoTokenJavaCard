package org.mycard;

import org.apache.commons.lang.RandomStringUtils;
import org.mycard.smartcard.ConsoleNotifier;
import org.mycard.smartcard.pcscWrapper.CAPDU;
import org.mycard.smartcard.pcscWrapper.RAPDU;
import org.mycard.smartcard.readerWrappers.CardReaderWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.mycard.common.ByteArrayHelper;
import org.mycard.smartcard.CardState;
import org.mycard.smartcard.CardStateWatcher;
import org.mycard.smartcard.INotifier;
import org.mycard.smartcard.pcscWrapper.helpers.Keys;
import org.apache.commons.io.FileUtils;


import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import java.io.*;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.mycard.common.ByteArrayHelper.bConcat;
import static org.mycard.common.ByteArrayHelper.bytes;
import static org.mycard.CardData.*;

/**
 * Created by Asus on 20.08.2019.
 */
public class HostAPI {

    public static CardStateWatcher getCardStateWatcher() {
        return cardStateWatcher;
    }

    private static CardStateWatcher cardStateWatcher;

    private final static Logger log = LoggerFactory.getLogger(HostAPI.class);

    public static CardReaderWrapper getCardReaderWrapper() {
        return cardReaderWrapper;
    }

    private static CardReaderWrapper cardReaderWrapper = null;

    private static CardState cardState = CardState.NOT_INSERTED;

    public static CardState getCardState() {
        return cardState;
    }


    public static void setAndStartCardsStateWatcher(INotifier notifier){
        cardStateWatcher = new CardStateWatcher("");
        cardStateWatcher.setNotifier(notifier);
        addCardsHandlers();
        cardStateWatcher.start();
    }

    private static void addCardsHandlers() {
        cardStateWatcher.onCardInserted(event -> {
            try {

                fillCardReaderAndCardState(event.cardChannel);

                if (cardReaderWrapper != null) {
                    log.debug("Card is reading...");

                    if (cardState != CardState.EMPTY){
                        log.debug("Applet is present on card...");
                    }
                    else{
                        log.debug("Card is empty...");
                    }

                } else {
                    log.debug("Card is not inserted!");
                }

                setCardReaderWrapperCurState();

            } catch (Throwable e1) {
                e1.printStackTrace();
                log.error("ERROR: " + e1.getMessage()); //todo: make better error reporting!
            }

            log.debug("===============================================================");

        });

        cardStateWatcher.onCardRemoved(event -> {
            cardReaderWrapper = null;

            setCardReaderWrapperCurState();

            log.error("No card!");
            log.debug("===============================================================");
        });

    }

    public static void refreshCardState() throws CardException {
        if (cardReaderWrapper != null)
            cardState = cardReaderWrapper.getAppletState(INSTANCE_AID);
    }

    private static void fillCardReaderAndCardState(CardChannel cardChannel) throws CardException {
        cardState = CardState.NOT_INSERTED;

        if (cardChannel != null) {
            cardReaderWrapper = new CardReaderWrapper(cardChannel);
            cardState = cardReaderWrapper.getAppletState(INSTANCE_AID);
        }
    }

    public static boolean getCardReaderWrapperCurState(){
        return cardReaderWrapper != null;
    }


    private static void setCardReaderWrapperCurState(){
        if (cardStateWatcher != null)
            cardStateWatcher.getCurState().setState(getCardReaderWrapperCurState());
    }


    public void install() throws Exception{
        log.debug("Start installing ...");

        //try {
            cardState = cardReaderWrapper.getAppletState(INSTANCE_AID);
            log.debug("Wallet Applet AID = " + INSTANCE_AID);

            switch (cardState) {
               /* case ON_GOING:
                case FINISHED:
                case INVALID:{
                    log.debug("Wallet Apple is installed! First you should delete it.");
                    break;
                }*/
                case EMPTY:{
                    log.debug("Client Applet is not installed!");

                    // generate host challenge for installation
                    byte[] hostChallenge = bytes(RandomStringUtils.random(16, "0123456789ABCDEF"));

                    //prepare cap file with Client Applet
                    File capFile = prepareCapFile();

                    Keys sdKeys = new Keys(
                            bytes(SD_ENC_KEY),
                            bytes(SD_MAC_KEY),
                            bytes(SD_DEC_KEY)
                    );

                    byte[] execLoadFileAid = bytes(LOAD_FILE_AID);
                    byte[] instanceAid = bytes(INSTANCE_AID);
                    byte[] execModuleAid = bytes(MODULE_AID);
                    byte[] managerAid = bytes(SD_AID);

                    log.debug("Start installing Wallet Applet...");

                    log.debug("Install App CAP file: " + capFile.getAbsolutePath());

                    //byte[] installData = new byte[0];

                    byte[] installData = bConcat(
                            new byte[]{MAX_PIN_ATTEMPTS},
                            new byte[]{PIN_LEN},
                            PIN
                    );

                    cardReaderWrapper.getReader().install(capFile, installData, execLoadFileAid, execModuleAid, instanceAid, sdKeys, managerAid, hostChallenge);

                    log.debug("Select Client Applet...");
                    cardReaderWrapper.getReader().selectAID(INSTANCE_AID);

                    refreshCardState();

                }
            }

        /*}
        catch (Exception e) {
            e.printStackTrace();
            log.error("ERROR: " + e.getMessage());
        }*/
    }


    public void removeApplet() {
        log.debug("Start removing...");
        try {
            byte[] hostChallenge = bytes(RandomStringUtils.random(16, "0123456789ABCDEF"));

            Keys sdKeys = new Keys(
                    bytes(SD_ENC_KEY),
                    bytes(SD_MAC_KEY),
                    bytes(SD_DEC_KEY)
            );

            byte[] execLoadFileAid = bytes(LOAD_FILE_AID);
            byte[] instanceAid = bytes(INSTANCE_AID);
            byte[] sdAid = bytes(SD_AID);

            //delete  applet
            cardReaderWrapper.getReader().delete(true, execLoadFileAid, instanceAid, sdKeys, sdAid, hostChallenge);

            log.debug("Client Applet is deleted!");

            refreshCardState();


        }
        catch (Exception e) {
            e.printStackTrace();
            log.error("ERROR: " + e.getMessage());
        }
    }



    public void printCardState(){
        switch (cardState) {
            case EMPTY: {
                log.debug("Applet is not installed! ");
                break;
            }
            case INSTALLED:{
                log.debug("Applet is installed!");
            }
            default:{
                log.debug("Card is not inserted!");
            }
        }
    }

    private File prepareCapFile() throws IOException {
       // InputStream is = this.getClass().getResourceAsStream("/wallet.cap");

        log.debug("start cap checking...");


       // byte[] buffer = new byte[is.available()];
       // is.read(buffer);

        File capFile = new File(CAP_PATH);

       // OutputStream outStream = new FileOutputStream(capFile);
        //outStream.write(buffer);

        //outStream.close();

        //is.close();
        if (!capFile.exists()) {
            throw  new IOException("Cap file lost!");
        }
        log.debug(capFile.getAbsolutePath());

        return capFile;
    }

    public static void testCard(CardTestTask cardTask) throws Exception
    {

        setAndStartCardsStateWatcher(new ConsoleNotifier());
        while (true) {
            CardState state = getCardState();

            System.out.println("Card status from main thread = " + state);

            if (state == CardState.INSTALLED) {
                cardTask.startTask();
                break;
            }

            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {}
        }
    }





}
