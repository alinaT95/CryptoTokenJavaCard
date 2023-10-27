package org.mycard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Scanner;

import org.mycard.smartcard.ConsoleNotifier;
import org.mycard.smartcard.CardState;

/**
 * Hello world!
 *
 */
public class AppletInstaller {
    private final static Logger log = LoggerFactory.getLogger(AppletInstaller.class);


    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);

        ConsoleNotifier consoleNotifier = new ConsoleNotifier();

        HostAPI.setAndStartCardsStateWatcher(consoleNotifier);

        System.out.println("Start installer...");
        try {
            while (true) {
                CardState state = HostAPI.getCardState();

                HostAPI walletHostApi = new HostAPI();
                System.out.println("Card status from main thread = " + state);

                switch (state) {
                    case EMPTY: { // Card is empty

                        log.debug("Press 0, if you want to install Wallet Applet onto the card");

                        if (sc.hasNextInt()) {
                            int input = sc.nextInt();

                            if (input == 0)
                                walletHostApi.install();
                        }

                        break;
                    }
                    case INSTALLED: { // Card is not empty

                        log.debug("Press 0, if you want to remove Wallet Applet from the card");

                        if (sc.hasNextInt()) {
                            int input = sc.nextInt();

                            if (input == 0)
                                walletHostApi.removeApplet();

                        }
                    }
                    default: {

                    }
                }

                try {
                    Thread.sleep(3000);
                } catch (InterruptedException e1) {
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            //HostAPI.getCardStateWatcher().stopCardStateWatcher();
        }

    }
}
