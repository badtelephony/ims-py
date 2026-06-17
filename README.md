# Python IMS client
This is a long project and someone needs to write this readme. I'm lazy so this will be a bad readme. If you use AI to make a readme and its not like blatantly wronng I'll probably accept it.


### Usage:
So you want to actually start https://github.com/fasferraz/SWu-IKEv2 first. For my Verizon sim card, it looks a bit like this:
`sudo .venv/bin/python3 swu_emulator.py -m 0 -a ims -M 311 -N 480 -d wo.vzwwo.com -n ims`
-M is your country code and -N is your carrier code. -d is your ePDG URL. If its 3gpp discovery compatible you can omit it. I'm going to be making a launcher which starts that (or strongswan) ims proxy and probably baresip automatically. If something failed here, make sure your sim card is in your smart card slot and PCSCD is running. Check `pcsc_scan` command and make sure your sim card is there.

Then, after you have a tunnel to your ePDG, you want to start ims_proxy. From swu_emulator you'll see a log line which looks like this
`P-CSCF IPV6 ADDRESS ['2001:4888:2:fe40:a0:104:0:2d4', '2001:4888:2:fe40:a0:104:0:2c8', '2001:4888:5:fe01:e0:104:0:2f8']`

Select one IP from there and run the ims_proxy like this:
```
sudo ip netns exec ims python3 ims_proxy.py --msisdn +1YOURPHONENUMBER  --write-account --baresip-accounts /root/.baresip/accounts --pcscf YOURPCSCF
```
You dont need the baresip account and write account but its useful for the next step, actually making the calls (btw you might need to make /root/.baresip).

Now, you're ready to make a call. You'll want baresip (with AMR configured)
`sudo ip netns exec ims baresip`. Should just work, you'll see green text saying "Useragent registered". If you see that you can make a phone call by pressing `d` on your keyboard and dialing a phone number (you need the +1 or whatever your countries dialer code is).

Um, pls contrib your carrier bundles to badtelephony-bundles <3

