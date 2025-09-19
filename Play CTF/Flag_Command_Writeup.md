# HackTheBox - Play CTF: Flag Command 🏴‍☠️

## Challenge Description  
> *Embark on the "Dimensional Escape Quest" where you wake up in a mysterious forest maze that's not quite of this world. Navigate singing squirrels, mischievous nymphs, and grumpy wizards in a whimsical labyrinth that may lead to otherworldly surprises.*  

This challenge drops us into a **browser-based text adventure game**, hosted on a container. The interface mimics a command-line terminal where we input commands to navigate the forest.  

---

## Step 1: Initial Recon  

First, we check the running service:  

```bash
whatweb http://94.237.123.160:46843
```  

Output:  

- Werkzeug/3.0.1 Python/3.11.8  
- Title: Flag Command  
- Static files: `/static/terminal/js/`  

This tells us the challenge is built in Python (Werkzeug dev server) with client-side JS running the game logic.  

---

## Step 2: Source Code Review  

Looking into `/static/terminal/js/main.js`, `/commands.js`, and `/game.js`, we find interesting mechanics:  

- Player commands are validated against `availableOptions`.  
- Commands are sent via POST requests to `/api/monitor`.  
- If a command response contains `HTB{}`, the game is won.  
- **Hidden Easter eggs** exist under `availableOptions['secret']`.  

This hints we need to dig for "secret commands" beyond the normal forest navigation.  

---

## Step 3: Enumerating Commands  

Through both source inspection and fuzzing, we find all possible commands. Let’s test each one and note the results.  

### Command List & Responses  

- **HEAD NORTH** → `What are you trying to break??`  
- **HEAD SOUTH** → `What are you trying to break??`  
- **HEAD EAST** → `What are you trying to break??`  
- **HEAD WEST** → `What are you trying to break??`  

---

- **GO DEEPER INTO THE FOREST** → *You venture deeper… trapped by fairies. Game over!*  
- **FOLLOW A MYSTERIOUS PATH** → *Unicorn ride → Magical realm (no flag).*  
- **CLIMB A TREE** → `What are you trying to break??`  
- **TURN BACK** → `What are you trying to break??`  

---

- **EXPLORE A CAVE** → *Bat rave party → Insanity. Game over!*  
- **CROSS A RICKETY BRIDGE** → *Bridge collapses → Game over!*  
- **FOLLOW A GLOWING BUTTERFLY** → *Butterfly transforms → Giant caterpillar. Game over!*  
- **SET UP CAMP** → *Peaceful night → Fire ants attack → You barely escape (survives).*  

---

- **ENTER A MAGICAL PORTAL** → *Grumpy wizard restroom → Game over!*  
- **SWIM ACROSS A MYSTERIOUS LAKE** → *Water nymphs exhaust you → Game over!*  
- **FOLLOW A SINGING SQUIRREL** → *Woodland party → Hangover. Game over!*  
- **BUILD A RAFT AND SAIL DOWNSTREAM** → *Capsized at waterfall → Game over!*  

---

### The Hidden Secret  

Finally, after inspecting the `secret` command list, we discover a nonsense phrase:  

```text
Blip-blop, in a pickle with a hiccup! Shmiggity-shmack
```  

Submitting this command to `/api/monitor` gives:  

```json
{
  "message": "HTB{...flag_here...}"
}
```  

And that’s the **real flag**! 🎉  

---

## Step 4: Lessons Learned  

1. **Never trust the UI** → The frontend may hide secret commands or logic.  
2. **Inspect JavaScript** → Always check `/static/js/` files for hidden routes and commands.  
3. **API awareness** → The `/api/monitor` endpoint is where all the magic happens.  
4. **Fuzzing + reading code** → Combining guessing with code review uncovers hidden paths.  

---

## Final Flag  
|| *Flag hidden in this writeup* ||
