"""
Production-grade async port scanner with proper resource management,
security controls, and comprehensive error handling.
"""

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Callable, Dict, Any
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanResult:
    """Structured scan result container."""
    host: str
    port: int
    is_open: bool
    service_name: Optional[str] = None
    banner: Optional[str] = None
    response_time_ms: Optional[float] = None
    scanned_at: datetime = field(default_factory=datetime.utcnow)
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "is_open": self.is_open,
            "service_name": self.service_name,
            "banner": self.banner,
            "response_time_ms": self.response_time_ms,
            "scanned_at": self.scanned_at.isoformat() if self.scanned_at else None,
            "error": self.error
        }


@dataclass
class ScanProgress:
    """Scan progress information."""
    scan_id: str
    status: ScanStatus
    total_hosts: int
    completed_hosts: int
    total_ports: int
    completed_ports: int
    open_ports_found: int
    current_target: Optional[str] = None
    message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "status": self.status.value,
            "total_hosts": self.total_hosts,
            "completed_hosts": self.completed_hosts,
            "total_ports": self.total_ports,
            "completed_ports": self.completed_ports,
            "open_ports_found": self.open_ports_found,
            "current_target": self.current_target,
            "message": self.message,
            "progress_percent": round((self.completed_ports / self.total_ports * 100), 2) if self.total_ports > 0 else 0
        }


class PortScanner:
    """
    Async port scanner with security guardrails and production features.
    """
    
    # Common service mappings
    COMMON_SERVICES = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
        25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp",
        80: "http", 110: "pop3", 119: "nntp", 143: "imap",
        161: "snmp", 194: "irc", 443: "https", 445: "smb",
        993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 5900: "vnc", 8080: "http-proxy",
        8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb"
    }
    
    # Default port presets
    PORT_PRESETS = {
        "quick": list(range(1, 1025)),
        "common": [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443],
        "extended": list(range(1, 1025)) + [1433, 1521, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 27017],
        "full": list(range(1, 65536)),
        "web": [80, 443, 8080, 8443, 3000, 4200, 5000, 8000, 9000],
        "database": [1433, 1521, 3306, 5432, 27017, 6379, 9200, 9300],
        "mail": [25, 110, 143, 465, 587, 993, 995]
    }
    
    def __init__(
        self,
        timeout: float = 2.0,
        max_concurrent: int = 100,
        rate_limit: Optional[int] = None,
        allowed_networks: Optional[List[str]] = None,
        progress_callback: Optional[Callable] = None
    ):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.rate_limit = rate_limit
        self.progress_callback = progress_callback
        self.allowed_networks = self._parse_allowed_networks(allowed_networks or [])
        self._cancelled = False
        
    def _parse_allowed_networks(self, networks: List[str]) -> List[ipaddress.ip_network]:
        """Parse and validate allowed network ranges."""
        parsed = []
        for net in networks:
            try:
                parsed.append(ipaddress.ip_network(net, strict=False))
            except ValueError as e:
                logger.warning(f"Invalid network range '{net}': {e}")
        return parsed
    
    def _is_target_allowed(self, target: str) -> bool:
        """Verify target is within authorized scanning scope."""
        if not self.allowed_networks:
            return True
            
        try:
            ip = ipaddress.ip_address(target)
            return any(ip in network for network in self.allowed_networks)
        except ValueError:
            return False
    
    def cancel(self):
        """Cancel the current scan."""
        self._cancelled = True
        
    def reset_cancel(self):
        """Reset cancellation flag."""
        self._cancelled = False
    
    async def resolve_target(self, target: str) -> str:
        """Resolve hostname to IP with validation."""
        if not re.match(r'^[a-zA-Z0-9.\-:]+$', target):
            raise ValueError(f"Invalid target format: {target}")
            
        try:
            ipaddress.ip_address(target)
            resolved = target
        except ValueError:
            try:
                loop = asyncio.get_event_loop()
                addrinfo = await loop.getaddrinfo(target, None, family=socket.AF_INET)
                resolved = addrinfo[0][4][0]
            except socket.gaierror as e:
                raise ValueError(f"Could not resolve hostname {target}: {e}")
        
        if not self._is_target_allowed(resolved):
            raise PermissionError(
                f"Target {target} ({resolved}) is outside authorized scanning scope. "
                f"Allowed networks: {[str(n) for n in self.allowed_networks]}"
            )
            
        return resolved
    
    async def grab_banner(self, reader: asyncio.StreamReader, port: int) -> Optional[str]:
        """Attempt to grab service banner."""
        try:
            probe = self._get_probe_for_port(port)
            if probe:
                # We need the writer to send the probe
                # This is handled in scan_port
                pass
            
            banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            decoded = banner.decode('utf-8', errors='ignore').strip()
            # Clean up non-printable characters
            decoded = ''.join(c if c.isprintable() or c in '\r\n\t' else '.' for c in decoded)
            return decoded[:512]  # Limit banner size
        except asyncio.TimeoutError:
            return None
        except Exception as e:
            logger.debug(f"Banner grab failed for port {port}: {e}")
            return None
    
    def _get_probe_for_port(self, port: int) -> Optional[bytes]:
        """Get appropriate probe for common services."""
        probes = {
            80: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            443: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            8080: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            25: b"EHLO scanner\r\n",
            110: b"USER test\r\n",
            143: b"a1 CAPABILITY\r\n",
            21: b"",  # FTP sends banner immediately
            22: b"",  # SSH sends banner immediately
        }
        return probes.get(port)
    
    async def scan_port(self, target_ip: str, port: int) -> ScanResult:
        """Scan a single port with proper resource management."""
        if self._cancelled:
            return ScanResult(
                host=target_ip,
                port=port,
                is_open=False,
                error="Scan cancelled"
            )
        
        start_time = asyncio.get_event_loop().time()
        writer = None
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port),
                timeout=self.timeout
            )
            
            response_time = (asyncio.get_event_loop().time() - start_time) * 1000
            
            # Send probe if applicable
            probe = self._get_probe_for_port(port)
            if probe:
                try:
                    writer.write(probe)
                    await writer.drain()
                    await asyncio.sleep(0.1)  # Give service time to respond
                except:
                    pass
            
            # Try to grab banner
            banner = await self.grab_banner(reader, port)
            
            # Properly close the connection
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except:
                pass
            
            return ScanResult(
                host=target_ip,
                port=port,
                is_open=True,
                service_name=self.COMMON_SERVICES.get(port),
                banner=banner,
                response_time_ms=round(response_time, 2)
            )
            
        except asyncio.TimeoutError:
            if writer:
                writer.close()
            return ScanResult(
                host=target_ip,
                port=port,
                is_open=False,
                response_time_ms=round(self.timeout * 1000, 2)
            )
        except ConnectionRefusedError:
            if writer:
                writer.close()
            return ScanResult(
                host=target_ip,
                port=port,
                is_open=False
            )
        except OSError as e:
            if writer:
                writer.close()
            return ScanResult(
                host=target_ip,
                port=port,
                is_open=False,
                error=str(e)
            )
        except Exception as e:
            if writer:
                writer.close()
            logger.error(f"Unexpected error scanning port {port}: {e}")
            return ScanResult(
                host=target_ip,
                port=port,
                is_open=False,
                error=str(e)
            )
    
    async def scan_host(
        self,
        target: str,
        ports: List[int],
        progress_callback: Optional[Callable] = None
    ) -> List[ScanResult]:
        """Scan multiple ports on a host with concurrency control."""
        target_ip = await self.resolve_target(target)
        logger.info(f"Scanning {target} ({target_ip}) on {len(ports)} ports")
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        completed = 0
        total = len(ports)
        open_count = 0
        
        async def scan_with_limit(port: int) -> ScanResult:
            nonlocal completed, open_count
            
            if self._cancelled:
                return ScanResult(
                    host=target_ip,
                    port=port,
                    is_open=False,
                    error="Scan cancelled"
                )
            
            async with semaphore:
                if self.rate_limit:
                    await asyncio.sleep(1.0 / self.rate_limit)
                
                result = await self.scan_port(target_ip, port)
                completed += 1
                
                if result.is_open:
                    open_count += 1
                
                if progress_callback:
                    try:
                        progress_callback({
                            "completed": completed,
                            "total": total,
                            "port": port,
                            "is_open": result.is_open,
                            "open_count": open_count,
                            "target": target
                        })
                    except Exception:
                        pass
                        
                return result
        
        tasks = [scan_with_limit(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_results = []
        for r in results:
            if isinstance(r, Exception):
                logger.error(f"Scan task failed: {r}")
            else:
                valid_results.append(r)
        
        return valid_results
    
    async def scan_targets(
        self,
        targets: List[str],
        ports: List[int],
        scan_id: str,
        progress_callback: Optional[Callable] = None
    ) -> Dict[str, List[ScanResult]]:
        """Scan multiple targets with progress tracking."""
        self.reset_cancel()
        all_results = {}
        total_hosts = len(targets)
        
        for idx, target in enumerate(targets):
            if self._cancelled:
                all_results[target] = []
                continue
                
            try:
                if progress_callback:
                    progress_callback({
                        "scan_id": scan_id,
                        "status": "running",
                        "total_hosts": total_hosts,
                        "completed_hosts": idx,
                        "total_ports": len(ports),
                        "completed_ports": idx * len(ports),
                        "open_ports_found": sum(len([r for r in all_results.get(t, []) if r.is_open]) for t in all_results),
                        "current_target": target,
                        "message": f"Scanning {target}"
                    })
                
                results = await self.scan_host(target, ports, progress_callback)
                all_results[target] = results
                
            except Exception as e:
                logger.error(f"Failed to scan {target}: {e}")
                all_results[target] = []
        
        return all_results
    
    @classmethod
    def get_preset_ports(cls, preset: str) -> List[int]:
        """Get ports for a named preset."""
        return cls.PORT_PRESETS.get(preset, cls.PORT_PRESETS["common"])
    
    @classmethod
    def get_available_presets(cls) -> List[str]:
        """Get list of available preset names."""
        return list(cls.PORT_PRESETS.keys())
