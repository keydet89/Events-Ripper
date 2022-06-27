# Events-Ripper
 This project is based on RegRipper, to easily extract additional value/pivot points from a TLN events file.

# Purpose
  Events-Ripper is based on the 5-field, pipe-delimited TLN "intermediate" events file format. This file is
  intermediate, as it the culmination or collection of normalized events from different data sources (i.e., 
  Registry, WEVTX, MFT, etc.) that are then parsed into a deduped timeline.
  
  The current iteration of Events-Ripper includes plugins that are written specifically for Windows Event 
  Log (*.evtx) events. 
  
  This tool is intended to address a very specific problem set, one that leverages a limited data set to 
  develop as much insight and situational awareness as possible from that data set. 
  
# Premise
  Events-Ripper is built on several core ideas:
  
  1. Windows Event Log records are best described as an event source/ID pair. This is due to the fact that 
     event IDs are not unique; a single event ID can apply to several different events.
	 
  2. Something learned on one engagement or during one incident may likely be extremely useful during a 
     future incident.
	 
  3. Much more data is available than is often thought from various data sources, especially the Windows 
     Event Log.
  
# Installation   
  To "install" Events-Ripper, simply download and extract all files to a folder, ensuring that "plugins"
  remains a subfolder.
  
# Usage
  To use Events-Ripper, start by creating the events file. Copy/extract Windows Event Log *.evtx files to a
  central location, and then use the included wevtx.bat to create an events file:
  
  wevtx.bat c:\case\*.evtx c:\case\events.txt
  
  Note that wevtx.bat relies on LogParser, which is included here, but also available from Microsoft. Wevtx.bat
  also uses evtxparse.exe, which (along with it's .pl source code) is also included in this distribution. The
  batch file does not do any error checking, so if wevtx.bat "fails" for some reason, try removing some of the 
  *.evtx files. 
  
  You can then add other timeline events data, using any of the tools in the Tools repository to this Github.
  
  Once you've completed adding data to the events file, and you're ready to parse the events file into a 
  timeline (or following doing so), you can easily create additional context/pivot points by running erip.exe.
  
  Similar to RegRipper, you can run a single plugin against the events file:
  
  erip -f c:\cases\events.txt -p failedlogins
  
  Or, you can run *all* plugins (you're so very welcome, Dray) against the events file:
  
  erip -f c:\cases\events.txt -add
  
  You can also list all of the plugins available:
  
  erip -l
  
  You can also list the plugins in CSV format:
  
  erip -l -c 
  
  Simply redirect the output to a file, and open that file in Excel. 