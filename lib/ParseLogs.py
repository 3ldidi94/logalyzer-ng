import re
import gzip

#
# ParseLogs.py
# Parsing component of Logalyzer.  Compiled in Python 2.6
#

# log object 
# Stuck into a dictionary by user:Log, where log houses
# logs, fails, successes, logged IPs, and commands used
class Log:
	# dump date of first log
	def first_date(self):
		if len(self.logs) > 0:
			date = None
			i = 0
			# sometimes the first few aren't right, so look
			# until we find one
			while i < len(self.logs) and date is None:
				date = ParseDate(self.logs[i])
				i += 1
			return date
	# dump date of last log
	def last_date(self):
		if len(self.logs) > 0:
			return ParseDate(self.logs[len(self.logs) - 1])
	def __init__(self, usr):
		'''
     		# LOGS = {
		#   "username": Log(
		#     usr       = "username",
		#     logs      = ["raw log line", ...],     # all log lines
		#     fail_logs = ["raw log line", ...],     # Failed password / auth failure
		#     succ_logs = ["raw log line", ...],     # Accepted password
		#     ips       = ["1.2.3.4", ...],          # IPs for this username
		#     commands  = ["/usr/bin/apt ...", ...]  # COMMAND= du sudo
		#   ),
		#   None: Log(...)  # when ParseUsr return None
		# }
		'''
		self.usr = usr
		self.logs = []
		self.fail_logs = []
		self.fail_logs_root = []
		self.succ_logs = []
		self.ips = []
		self.commands = []
		self.bruteforce_logs = []
		self.sudo_fail_logs = []
		self.su_fail_logs = []
		self.account_events = []

# parse user from various lines
def ParseUsr(line):
	usr = None
	if "Accepted password" in line:
		usr = re.search(r'(\bfor\s)(\w+)', line)
	elif "Failed password for" in line and "invalid user" not in line:
		usr = re.search(r'(\bfor\s)(\w+)', line)
	elif "sudo:" in line:
		usr = re.search(r'(sudo:\s+)(\w+)', line)
	elif "authentication failure" in line:
		usr = re.search(r'(USER=)(\w+)', line)
		if usr is None:
			usr = re.search(r'(user=)(\w+)', line)
	elif "for invalid user" in line:
		usr = re.search(r'(\buser\s)(\w+)', line)
	if usr is not None:
		return usr.group(2)

# parse an IP from a line
def ParseIP(line):
	ip = re.search(r'(\bfrom\s)(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)', line)
	if ip is not None:
		return ip.group(2)

# parse a date from the line
def ParseDate(line):
	date = re.search(r'^[A-Za-z]{3}\s*[0-9]{1,2}\s[0-9]{1,2}:[0-9]{2}:[0-9]{2}', line)
	if date is not None:
		return date.group(0)

# parse a command from a line
def ParseCmd(line):
	# parse command to end of line 
	cmd = re.search(r'(\bCOMMAND=)(.+?$)', line)
	if cmd is not None:
		return cmd.group(2)

def is_gzip(path):
	try:
		with open(path, 'rb') as f:
			return f.read(2) == b'\x1f\x8b'
	except Exception:
		return False

# begin parsing the passed LOG
def ParseLogs(LOG):
	# initialize the dictionary
	logs = {}

	# parse the log — auto-detect gzip via magic bytes
	f = None
	try:
		f = gzip.open(LOG, 'rt', encoding='utf-8') if is_gzip(LOG) else open(LOG, 'r', encoding='utf-8')
		log = f.read()
	except Exception as e:
		print('[-] Error opening \'%s\': %s'%(LOG,e))
		return None
	finally:
		if f is not None: f.close()

	for line in log.split('\n'):
		# match a login
		if "Accepted password for" in line:
			usr = ParseUsr(line)
			
			# add 'em if they don't exist
			if not usr in logs:
				logs[usr] = Log(usr)
			
			ip = ParseIP(line)
			# set info
			if not ip in logs[usr].ips:
				logs[usr].ips.append(ip)
			logs[usr].succ_logs.append(line.rstrip('\n'))
			logs[usr].logs.append(line.rstrip('\n'))

		# match a failed login
		elif "Failed password for" in line:
			# parse user
			usr = ParseUsr(line)

			if not usr in logs:
				logs[usr] = Log(usr)
				
			ip = ParseIP(line)

			if not ip in logs[usr].ips:
				logs[usr].ips.append(ip)
			logs[usr].fail_logs.append(line.rstrip('\n'))
			logs[usr].logs.append(line.rstrip('\n'))
			
		# match failed auth
		elif ":auth): authentication failure;" in line:
			# so there are three flavors of authfail we care about;
			# su, sudo, and ssh.  Lets parse each.
			usr = re.search(r'(\blogname=)(\w+)', line)
			if usr is not None:
				usr = usr.group(2)
			# parse a fail log to ssh
			if "(sshd:auth)" in line:
				# ssh doesn't have a logname hurr
				usr = ParseUsr(line)
				ip = ParseIP(line)
				if not usr in logs:
					logs[usr] = Log(usr)
				logs[usr].ips.append(ParseIP(line))
			# parse sudo/su fails
			else:	
				if not usr in logs:
					logs[usr] = Log(usr)
			logs[usr].fail_logs.append(line.rstrip('\n'))
			logs[usr].logs.append(line.rstrip('\n'))
			# match commands
		elif "sudo:" in line:
			# parse user
			usr = ParseUsr(line)
			if not usr in logs:
				logs[usr] = Log(usr)
	
			cmd = ParseCmd(line)
			# append the command if it isn't there already
			if cmd is not None:
				if not cmd in logs[usr].commands:
					logs[usr].commands.append(cmd)
			logs[usr].logs.append(line.rstrip('\n'))

		# brute-force détecté par sshd
		elif "Too many authentication failures" in line:
			usr = re.search(r'authenticating user (\w+)', line)
			usr = usr.group(1) if usr else None
			if usr not in logs:
				logs[usr] = Log(usr)
			ip = ParseIP(line)
			if ip and ip not in logs[usr].ips:
				logs[usr].ips.append(ip)
			logs[usr].bruteforce_logs.append(line.rstrip('\n'))
			logs[usr].logs.append(line.rstrip('\n'))

		# tentative sudo refusée (NOT in sudoers)
		elif "NOT in sudoers" in line:
			usr = re.search(r'sudo:\s+(\w+)', line)
			usr = usr.group(1) if usr else None
			if usr not in logs:
				logs[usr] = Log(usr)
			logs[usr].sudo_fail_logs.append(line.rstrip('\n'))
			logs[usr].logs.append(line.rstrip('\n'))

		# tentative su échouée
		elif "FAILED su for" in line:
			target = re.search(r'FAILED su for (\w+)', line)
			attacker = re.search(r'\bby (\w+)', line)
			usr = attacker.group(1) if attacker else None
			if usr not in logs:
				logs[usr] = Log(usr)
			logs[usr].su_fail_logs.append(line.rstrip('\n'))
			logs[usr].logs.append(line.rstrip('\n'))

		# création / modification / suppression de comptes
		elif any(kw in line for kw in ("new user:", "new group:", "delete user", "usermod:", "useradd:", "userdel:")):
			if "_system" not in logs:
				logs["_system"] = Log("_system")
			logs["_system"].account_events.append(line.rstrip('\n'))
			logs["_system"].logs.append(line.rstrip('\n'))

	return logs