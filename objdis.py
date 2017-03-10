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
IMM = re.compile("#0x([a-f0-9]+)")

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
	m = IMM.match(operand)
	if m:
		return ('i', int(m.group(1),16))
	return ('?', operand)

class Instr(object):

	def __init__(self, addr, opc, *operands):
		self.opcode = opc
		self.address = addr
		self.operands = list(operands)
		self.optypes = map(optype, operands)
		i = 0
		# join adresses & symbols
		# remove comments
		while i < len(self.optypes)-1:
			if self.optypes[i][0] == 'a' and self.optypes[i+1][0] == 's':
				self.optypes[i] = ('a',
					self.optypes[i][1], self.optypes[i+1][1], self.optypes[i+1][2])
				del self.optypes[i+1]
				self.operands[i] += ' ' + self.operands[i+1]
				del self.operands[i+1]
			if self.optypes[i][0] == '?' and self.optypes[i][1] == '//':
				del self.optypes[i:]
				del self.operands[i:]
			i += 1

	def __repr__(self):
		return self.opcode + str(self.optypes)

	def __str__(self):
		return self.opcode + ' ' + ' '.join(self.operands)

	def match(self, opc, *operands):
		if not re.match(opc,self.opcode):
			return False
		var = {}
		for x,y in zip(self.optypes, operands):
			if y in 'xyz':
				if x[0] != 'r': return False
				if y in var:
					if x[1] != var[y]: return False
				else:
					var[y] = x[1]
			if y in 'rasim' and not x[0] == y: return False
		return True

def find_insns(insns, *filt):
	return [x for x in insns if x.match(*filt)]

def dis(file):
	insns = []
	for line in file:
		m = S_LINE.match(line)
		if not m: continue
		tokens = line.split()
		tokens = [re.sub(',$','',x) for x in tokens]
		insns.append(Instr(tokens[0],tokens[2],*tokens[3:]))
	return insns

def test(insns):
	print '\n'.join(map(str,insns))
	l = find_insns(insns,'b')
	print '\n'.join(map(repr,l))
	
	
#	l = find_insns(insns,'ldr','r')
#	print '\n'.join(map(repr,l))
#	l = find_insns(insns,'add','x','x')
#	print '\n'.join(map(repr,l))
#	l = find_insns(insns,'add','x','y')
#	print '\n'.join(map(repr,l))
#	l = find_insns(insns,'','x','y')

#		if instr.match('st'):
#			print "store %s" % repr(instr)
#		if instr.match('b'):
#			print "branch %s" % repr(instr)
#		if instr.match('mov'):
#			print "mov %s" % repr(instr)

def main():
	with open(sys.argv[1],"rb") as f:
		insns = dis(f)
		test(insns)

if __name__ == '__main__':
	main()
