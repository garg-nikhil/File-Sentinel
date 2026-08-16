const text = `ALTERNATIVE CONTROL EVIDENCE
Option A: Synthetic GPO export confirms USB storage is blocked.
GPO Name: USB_BLOCK
Status: APPLIED`;
const labeledMatch = text.match(/(?:Employee(?:\s*Name)?|Agent(?:\s*(?:\/|\&)\s*Employee)?(?:\s*Name)?|Staff(?:\s*Name)?|Candidate(?:\s*Name)?|Participant(?:\s*Name)?|Director|VP|Name|User|Officer|Person|To certify that)[:,\s]+([A-Za-z\.\'\- ]{2,35})(?=[\r\n]|$)/i);
console.log(labeledMatch);
