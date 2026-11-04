# SwagShop

**Category:** web / business logic flaw (negative quantity) · **Course:** Offensive Security (PoliTo)

## Vulnerability

The shopping cart accepts negative item quantities and multiplies price × quantity with no lower-bound validation, letting the computed total go negative.

## Exploitation

Add a negative quantity of an item to the cart (e.g. `-N` shirts) to drive the total price below zero, effectively getting the store to owe the "customer" money / bypass the payment check entirely, in exchange for compensating with a legitimate positive-quantity item to balance the checkout logic.

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.

## Note

Only the solution notes were preserved for this challenge (no app source/handout retained); the original prompt/PDF (`LAB01_logic_vulns.pdf`) covered the full lab.
