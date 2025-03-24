import os
from typing import Dict, Any, Optional, List
from utils.logger import get_logger

logger = get_logger(__name__)

class ModelRegistry:
    def __init__(self, models_directory):
        self.models_directory = models_directory
        self.models = {}
        self.load_models()
        
    def load_models(self):
        logger.info(f"Loading ML models from {self.models_directory}")
        
        # Check if models directory exists
        if not os.path.exists(self.models_directory):
            logger.warning(f"Models directory {self.models_directory} does not exist")
            return
            
        # In a real system, this would scan the directory and load each model
        # For now, we'll just log the model directories we find
        for model_dir in [d for d in os.listdir(self.models_directory) 
                          if os.path.isdir(os.path.join(self.models_directory, d))]:
            logger.info(f"Found model directory: {model_dir}")
            
    def get_model(self, model_name):
        if model_name in self.models:
            return self.models[model_name]
        logger.warning(f"Model {model_name} not found in registry")
        return None
        
    def list_models(self):
        return list(self.models.keys())
