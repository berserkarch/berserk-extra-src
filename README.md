![Berserk Extra SRC](https://placehold.co/800x200/282a36/f8f8f2?text=Berserk+Extra+SRC)

## Installation

Get keys on the system

```bash
sudo pacman-key --init
sudo pacman-key --populate
sudo pacman-key --recv-keys B024DCEFADEF4328B5E3A848E7E0F2B78484DACF
sudo pacman-key --lsign-key B024DCEFADEF4328B5E3A848E7E0F2B78484DACF
sudo pacman -Syy --noconfirm
```

Then add the following code snippet to your `/etc/pacman.conf`:

```bash
# Entry in file /etc/pacman.conf:
[berserkarch-core]
SigLevel = Required DatabaseOptional
Include = /etc/pacman.d/berserk-mirrorlist

[berserkarch-aur]
SigLevel = Required DatabaseOptional
Include = /etc/pacman.d/berserk-mirrorlist

[berserkarch-extra]
SigLevel = Required DatabaseOptional
Include = /etc/pacman.d/berserk-mirrorlist
```

Then, run `sudo pacman -Sy` to update repository.
