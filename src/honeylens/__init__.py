"""HoneyLens sensor 1.0.

An installable package, not loose modules copied to /opt/sensor. In 0.9 every process
depended on the interpreter having the right working directory — when it did not, the
LLM honeypot fell over with "No module named 'core'" and for ten weeks silently lost
every event, while the systemd unit reported "active" the whole time. An installed
package cannot fail that way.
"""

__version__ = "1.0.0.dev0"
