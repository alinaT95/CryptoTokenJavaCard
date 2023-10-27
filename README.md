# Introduction

This repository contains exemplary applet providing standard functionality of crypto token (RSA signature and AES encryption/decryption). Applet code is placed in _CardTask_ subfolder. In _CardInstallerAndRunner_ subfolder there is a console Java-wriiten tool for applet installation/deleting and testing.

# Prerequisites

- Install Java Development Kit (JDK) 8.  Don't forget to set JAVA_HOME enviromet variable.
- Download Java Card Development Kit (JCDK). You can use JCDK 3.0.4 placed in _tools_ subfolder. Set JC_HOME enviroment variable pointing to your JCDK folder.
- Install Maven (or use Intellij Idea).
- You need smart card supporting JavaCard 3.0.4+ and Global Platform 2.1.1, SCP02.

# Applet building

- Run command _mvn install_ in the root of _CardTask_ project. It compiles sources and generates _.cap_ file. The cap file is copied into the root of _CardInstallerAndRunner_ for further usage. So be sure that both subprojects _CardTask_ and _CardInstallerAndRunner_ are at the same level.

_Note:_ _CardTask_ project is configured exactly for Java Card 3.0.4. So if you want use more fresh JCDK, you must fix pom.xml and rebuild.

# Applet installation onto simulator

You can try install applet onto simulator.

- In separate cmd instance run simulator by running _$JC_HOME$/bin/cref.bat_.
- Use _$JC_HOME$/bin/scriptgen.bat_ to generate script for applet installation onto simulator (based on cap file).
- Run the script in separate cmd instance using _$JC_HOME$/bin/apdutool.bat_.

# Applet installation onto real card

If you have card supporting Java Card 3.0.4 (like we do) or older, you can install applet onto it.

_Note:_ For Java Card 3.0.4 you may need exactly JDK 8. This is because more fresh JDK may cause troubles during applet compilation/installation. To install applet onto card we need to compile with target = 1.5, that is not supported for latest JDK. At the meantime target 1.6+ may cause applet istallation fail for card supporting only Java Card 3.0.4.

- In _CardInstallerAndRunner_ there is an implementation of secure applets installation flow based on Global Platform 2.1.1 specification. You need card supporting SCP02. Other SCP versions are not supported yet.
  
- Connect your card to PC (it could be contact or contactless card) using reader. Run com.mycard.AppletInstaller main function. It reads the card, detects if applet is installed or not. If it instakked already you have an option to delete it (together with related package).

- After applet istallation you may try unit tests demonstarting basic scenarious to work with the card.
