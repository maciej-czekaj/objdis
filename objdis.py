#!/usr/bin/env python

import sys, re

#S_LINE = re.compile("\s+([0-9a-f]+):\s+([0-9a-f]+)\s+(\S+)\s+([^,\s]+)(, ([^,\s]+)){0-2}.*")
#S_LINE = re.compile("\s+([0-9a-f]+):\s+([0-9a-f]+)\s+(\S+)\s+([^,\s]+)(?:,\s((:?[^,\[\]\s]+)|(:?\[\S+\]))){0,2}(?:\s<(\S+)>)?.*")
#OPERAND = "(\[([a-z][a-z0-9]*),#(-?\d+)\]!?)|([a-z][a-z0-9]*)|(#0x[a-f0-9]+)"
#S_LINE = re.compile("\s+([0-9a-f]+):\s+([0-9a-f]+)\s+(\S+)\s+([^,\s]+)(:?"+OPERAND+").*")

S_LINE = re.compile("\s+([0-9a-f]+):\s+([0-9a-f]+).*")
REG = re.compile("[a-z][a-z0-9]*")
REG_MEM = re.compile("\[([a-z][a-z0-9]*)(?:,#(-?\d+))?\](!)?")
#ADDR = re.compile("([0-9a-f]+) <([\w_]+)\+0x([0-9a-f]+)")
ADDR = re.compile("[0-9a-f]+")
SYM = re.compile("<([\w_]+)(?:\+0x([0-9a-f]+))?>")

def optype(operand):
	if REG.match(operand):
		return ('r',operand)
	m = REG_MEM.match(operand)
	if m:
		reg, disp, mod = m.groups()
		disp = 0 if disp is None else int(disp)
		return ('m', reg, disp, mod) 
	m = ADDR.match(operand)
	if m:
		return ('a', m.group(0))
	m = SYM.match(operand)
	if m:
		sym, off = m.groups()
		off = 0 if off is None else int(off,16)
		return ('s', sym, off)
	return ('?', operand)

class Instr(object):

	def __init__(self, opc, *operands):
		self.opcode = opc
		self.operands = operands
		self.optypes = map(optype, operands)

	def __repr__(self):
		return self.opcode + str(self.optypes)

	def __str__(self):
		return self.__repr__()

	def match(self, opc, *operands):
		if not re.match(opc,self.opcode):
			return False
		for x,y in zip(self.optypes, operands):
			if x[0] != y[0]: return False
		return True
			
def dis(file):
	insns = []
	for line in file:
		m = S_LINE.match(line)
		if not m: continue
		tokens = line.split()
		tokens = [re.sub(',$','',x) for x in tokens]
		insns.append(Instr(tokens[2],*tokens[3:]))
	print '\n'.join(map(str,insns))
	for instr in insns:
		if instr.match('ldr','r'):
			print "load %s" % instr
		if instr.match('st'):
			print "store %s" % instr
		if instr.match('b'):
			print "branch %s" % instr

def main():
	with open(sys.argv[1],"rb") as f:
		dis(f)

if __name__ == '__main__':
	main()
