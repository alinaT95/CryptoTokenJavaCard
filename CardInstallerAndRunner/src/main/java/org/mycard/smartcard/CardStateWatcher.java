package org.mycard.smartcard;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;


public class CardStateWatcher {
    final private static Logger log = LoggerFactory.getLogger(CardStateWatcher.class);

    private INotifier notifier;

    private CardReaderWrapperState prevState = new CardReaderWrapperState(false);
    private CardReaderWrapperState curState = new CardReaderWrapperState(false);

    private boolean cardStateWatcherIsOngoing = true;

    public void stopCardStateWatcher() {
        cardStateWatcherIsOngoing = false;
    }

    public CardReaderWrapperState getPrevState() {
        return prevState;
    }

    public CardReaderWrapperState getCurState() {
        return curState;
    }

    public static class Event {
    }

    public static class CardInsertedEvent extends Event {
        public CardChannel cardChannel = null;
    }

    private String terminalName;

    private List<Consumer<CardInsertedEvent>> insertedListeners = new ArrayList<>();
    private List<Consumer<Event>> removedListeners = new ArrayList<>();


    public void setNotifier(INotifier notifier) {
        this.notifier = notifier;
    }


    public void onCardInserted(Consumer<CardInsertedEvent> listener) {
        insertedListeners.add(listener);
    }


    public void onCardRemoved(Consumer<Event> listener) {
        removedListeners.add(listener);
    }

    public CardStateWatcher(String terminalName) {
        this.terminalName = terminalName;
    }


    public void start() {
        new Thread(() -> {
            while (cardStateWatcherIsOngoing) {
                try {
                    CardTerminals terminals = null;

                    Class pcscTerminal = Class.forName("sun.security.smartcardio.PCSCTerminals");
                    Field contextId = pcscTerminal.getDeclaredField("contextId");
                    contextId.setAccessible(true);

                    //if(contextId.getLong(pcscTerminal) != 0L)
                    //{
                    // First get a new context value
                    Class pcsc = Class.forName("sun.security.smartcardio.PCSC");
                    Method SCardEstablishContext = pcsc.getDeclaredMethod(
                            "SCardEstablishContext",
                            new Class[]{Integer.TYPE}
                    );
                    SCardEstablishContext.setAccessible(true);

                    Field SCARD_SCOPE_USER = pcsc.getDeclaredField("SCARD_SCOPE_USER");
                    SCARD_SCOPE_USER.setAccessible(true);

                    long newId = ((Long) SCardEstablishContext.invoke(pcsc,
                            new Object[]{SCARD_SCOPE_USER.getInt(pcsc)}
                    ));
                    contextId.setLong(pcscTerminal, newId);


                    // Then clear the terminals in cache
                    TerminalFactory factory = TerminalFactory.getDefault();
                    terminals = factory.terminals();
                    Field fieldTerminals = pcscTerminal.getDeclaredField("terminals");
                    fieldTerminals.setAccessible(true);
                    Class classMap = Class.forName("java.util.Map");
                    Method clearMap = classMap.getDeclaredMethod("clear");

                    clearMap.invoke(fieldTerminals.get(terminals));
                    //  }


                    // IF READERS ARE NOT INSERTED

                    prevState.setState(curState.getState());

                    if (terminals.list().isEmpty()) throw new RuntimeException("No readers connected");

                    CardTerminal terminal = terminals.list().get(0);

                    if (terminal.isCardPresent()) {
                        Card connect = terminal.connect("*");
                        CardChannel cardChannel = connect.getBasicChannel();
                        fireInsert(cardChannel);

                        if (!curState.equals(prevState)) {
                            String msg = setNotifierMessage();
                            notifier.notify(msg);
                        }

                        terminal.waitForCardAbsent(Long.MAX_VALUE);
                    } else {
                        fireRemove();
                        if (!curState.equals(prevState)) {
                            String msg = setNotifierMessage();
                            notifier.notify(msg);
                        }
                        terminal.waitForCardPresent(3000 /*Long.MAX_VALUE*/);
                    }


                    log.debug("===============================================================");
                    log.debug("===============================================================");
                    log.debug("===============================================================");


                } catch (Throwable e) {
                    fireRemove();
                    if (!curState.equals(prevState)) {
                        String msg = setNotifierMessage();
                        notifier.notify(msg);
                    }
                    e.printStackTrace();
                    log.error("Could not fetch list of readers, wait 3 seconds");
                    try {
                        Thread.sleep(3000);
                    } catch (InterruptedException e1) {
                    }
                }
            }
        }).start();
    }

    private String setNotifierMessage() {
        String stateTransition = prevState.getState() + curState.getState();
        log.debug(stateTransition);

        String msg;

        switch (stateTransition) {
            case "12": { //"0 -> 1"
                msg = "Client Card is inserted!";
                break;
            }

            case "21": { //"1 -> 0"
                msg = "Client Card is extracted!";
                break;
            }

            default: {
                msg = "Errors with card states has occurred!";
            }

        }

        return msg;
    }


    private void fireInsert(CardChannel cardChannel) throws CardException {
        CardInsertedEvent event = new CardInsertedEvent();
        event.cardChannel = cardChannel;
        for (Consumer<CardInsertedEvent> listener : insertedListeners) {
            listener.accept(event);
        }
    }

    private void fireRemove() {
        for (Consumer<Event> listener : removedListeners) {
            listener.accept(new Event());
        }
    }
}

