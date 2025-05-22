# Event Fadeout Table Merging
  
Allows for multiple mods to add new entries to the event fadeout table file, these fadeouts are used when an event is ending.


# How to Use
Add this mod as a dependency to your mod of choice  
Inside your mod, add a folder named "evt"  
Inside this "evt" folder, create a txt file named "evtFadeoutData.txt"


Then, inside the txt file, format the data the following way:  

major | minor | fade
  
Example:  
128 | 4 | 14

The given example would give the event of major id 128 and minor id 4 (e128_005 in the game files) a fadeout value of 14 (this is the "Entering the Metaverse" transition effect).  

![metaverse transition example](https://i.imgur.com/0AVGS5E.png)


For user convenience, here are the fadeout values I have found, if you find any of them are wrong, please open an issue and list the correct description for the value:  
| Fadeout ID | Description |
|-----------|-------------|
| 00 | Default |
| 01 | Default |
| 02 | Crowd Walking |
| 03 | PT Joker Jumps out |
| 04 | PT Joker Jumps out |
| 05 | Screen Wipe Effect |
| 06 | Crowd Walking |
| 07 | Crowd Walking |
| 08 | Train Transition |
| 09 | Crowd Walking |
| 10 | Crowd Walking |
| 11 | Umbrella Fadeout |
| 12 | Freezes screen until fadein, cloth removal effect on fadein |
| 13 | Screen freeze, unfreezes on fadein |
| 14 | Entering Metaverse |
| 15 | Phantom Thief Joker take your time portrait fadeout |
| 16 | Flashback fadeout (screen goes white) |
| 17 | Entering Velvet Room |
| 18 | Fast screen wipe |
| 19 | Exiting Velvet Room |
| 20 | Morgana bus fadeout |
| 21 | School trip airplane fadeout |
| 22 | Rapid date change/Sae interrogation |
| 23 | Entering Velvet Room |
| 24 | Entering Metaverse |
| 25 | Entering Metaverse to black screen |
| 26 | Fade to black, fadein is Metaverse entrance |
| 27 | Crowd Walking |
| 28 | Phantom Thief Joker take your time portrait fadeout |
| 29 | Crowd Walking (Beach) |
| 30 | Screen freeze, unfreezes on fadein |
