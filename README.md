# Introduction

This repository contains exemplary applet providing standard functionality of crypto token (RSA signature and AES encryption/decryption). Applet code is placed in _CardTask_ subfolder. In _CardInstallerAndRunner_ subfolder there is a console Java-wriiten tool for applet installation/deleting and testing.

# Prerequisites

- Install Java Development Kit (JDK) 8.  Don't forget to set JAVA_HOME enviromet variable.
- Download Java Card Development Kit (JCDK). You can use JCDK 3.0.4 placed in _tools_ subfolder. Set JC_HOME enviroment variable pointing to your JCDK folder.
- Install Maven (or use Intellij Idea).
- You may need smart card supporting JavaCard 3.0.4+ and Global Platform 2.1.1, SCP02.

# Applet building

- Run command _mvn install_ in the root of _CardTask_ project. It compiles sources and genreates _.cap_ file. The cap file is copied into the root of _CardInstallerAndRunner_.

# Applet installation onto simulator

You can try install applet onto simulator.

- In separate cmd instance run simulator by running _$JC_HOME$/bin/cref.bat_.
- Use _$JC_HOME$/bin/scripgen.bat_ to generate script for applet installation onto simulator (based on cap file).
- Run the script in separate cmd instance using _$JC_HOME$/bin/apdutool.bat_.

# Applet installation onto real card

You can try to install

_Note:_ Older versions of JDK may cause troubles during applet compilation since we need target = 1.5.
