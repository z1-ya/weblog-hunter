"""
Configuration management for weblog-hunter
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


@dataclass
class Config:
    """Configuration settings for weblog-hunter"""
    
    # Analysis settings
    min_requests: int = 50
    top_ips: int = 10
    
    # Output settings
    output_formats: List[str] = None
    output_directory: str = "."
    
    # Performance settings
    threads: int = 4
    max_memory_mb: Optional[int] = None
    show_progress: bool = True
    
    # Feature flags
    verbose: bool = False
    quiet: bool = False
    
    def __post_init__(self):
        if self.output_formats is None:
            self.output_formats = ["md"]
    
    @classmethod
    def from_file(cls, config_path: str) -> "Config":
        """
        Load configuration from YAML file
        
        Args:
            config_path: Path to YAML config file
            
        Returns:
            Config object
        """
        if not YAML_AVAILABLE:
            raise ImportError("PyYAML is required for config file support. Install with: pip install pyyaml")
        
        with open(config_path, "r") as f:
            data = yaml.safe_load(f)
        
        # Extract settings from nested structure
        config_dict = {}
        
        if "analysis" in data:
            config_dict.update({
                "min_requests": data["analysis"].get("min_requests", 50),
                "top_ips": data["analysis"].get("top_ips", 10),
            })
        
        if "output" in data:
            config_dict.update({
                "output_formats": data["output"].get("formats", ["md"]),
                "output_directory": data["output"].get("directory", "."),
            })
        
        if "performance" in data:
            config_dict.update({
                "threads": data["performance"].get("threads", 4),
                "max_memory_mb": data["performance"].get("max_memory_mb"),
            })
        
        return cls(**config_dict)
    
    def merge_cli_args(self, args) -> None:
        """
        Merge CLI arguments into config (CLI takes precedence)
        
        Args:
            args: Parsed argparse arguments
        """
        if hasattr(args, "min_req") and args.min_req is not None:
            self.min_requests = args.min_req
        
        if hasattr(args, "top") and args.top is not None:
            self.top_ips = args.top
        
        if hasattr(args, "verbose") and args.verbose:
            self.verbose = True
        
        if hasattr(args, "quiet") and args.quiet:
            self.quiet = True
            self.show_progress = False
