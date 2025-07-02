"""
Fine-tuning module for CyberSentinel AI - ATITA
Uses LoRA/PEFT for lightweight domain adaptation of TinyLlama
"""

import os
import json
from typing import Dict, Any, List, Optional
from pathlib import Path
import torch
from transformers import (
    AutoTokenizer, AutoModelForCausalLM, 
    TrainingArguments, Trainer, DataCollatorForLanguageModeling,
    PreTrainedTokenizer
)
from transformers.data.data_collator import DataCollatorForLanguageModeling
from peft import LoraConfig, get_peft_model, TaskType
from datasets import Dataset
from core.config import settings
from core.logging import get_logger

logger = get_logger("finetuning")

class TinyLlamaFineTuner:
    """Fine-tuner for TinyLlama using LoRA/PEFT"""
    
    def __init__(self):
        self.model_name = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
        self.tokenizer: Optional[PreTrainedTokenizer] = None
        self.model: Optional[AutoModelForCausalLM] = None
        self.peft_model = None
        self.finetuned_model_path = Path(settings.finetuning_model_path)
        self.finetuned_model_path.mkdir(parents=True, exist_ok=True)
        
    def load_base_model(self):
        """Load base TinyLlama model and tokenizer"""
        try:
            logger.info(f"Loading base model: {self.model_name}")
            
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            if self.tokenizer is not None and self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            
            # Load model
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                torch_dtype=torch.float16,
                device_map="auto" if torch.cuda.is_available() else None
            )
            
            logger.info("Base model loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load base model: {e}")
            return False
    
    def setup_lora_config(self) -> LoraConfig:
        """Set up LoRA configuration"""
        return LoraConfig(
            task_type=TaskType.CAUSAL_LM,
            inference_mode=False,
            r=settings.finetuning_lora_r,
            lora_alpha=settings.finetuning_lora_alpha,
            lora_dropout=settings.finetuning_lora_dropout,
            target_modules=["q_proj", "v_proj", "k_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]
        )
    
    def prepare_training_data(self, training_data: List[Dict[str, Any]]) -> Dataset:
        """Prepare training data for fine-tuning"""
        try:
            # Format data for instruction fine-tuning
            formatted_data = []
            
            for item in training_data:
                # Create instruction format
                instruction = f"""Analyze this cybersecurity threat and provide detailed reasoning:

Threat Data:
- Title: {item.get('title', 'N/A')}
- Description: {item.get('description', 'N/A')}
- Source: {item.get('source', 'N/A')}
- Type: {item.get('threat_type', 'N/A')}
- Severity: {item.get('severity', 'N/A')}

Analysis:
{item.get('analysis', 'No analysis available')}

Reasoning:
{item.get('reasoning', 'No reasoning provided')}

Immediate Actions:
{item.get('immediate_actions', 'No actions specified')}"""
                
                formatted_data.append({
                    "text": instruction,
                    "threat_type": item.get('threat_type', 'unknown'),
                    "severity": item.get('severity', 'unknown'),
                    "confidence": item.get('confidence', 0.5)
                })
            
            # Create dataset
            dataset = Dataset.from_list(formatted_data)
            logger.info(f"Prepared {len(formatted_data)} training examples")
            
            return dataset
            
        except Exception as e:
            logger.error(f"Failed to prepare training data: {e}")
            raise
    
    def tokenize_function(self, examples):
        """Tokenize function for dataset processing"""
        if self.tokenizer is None:
            raise RuntimeError("Tokenizer not loaded")
        return self.tokenizer(
            examples["text"],
            truncation=True,
            padding=True,
            max_length=512,
            return_tensors="pt"
        )
    
    def train(self, training_data: List[Dict[str, Any]], 
              validation_data: Optional[List[Dict[str, Any]]] = None,
              epochs: int = 3, batch_size: int = 4):
        """Train the model using LoRA fine-tuning"""
        try:
            if not self.load_base_model():
                raise RuntimeError("Failed to load base model")
            
            if self.tokenizer is None:
                raise RuntimeError("Tokenizer not loaded")
            
            # Set up LoRA configuration
            lora_config = self.setup_lora_config()
            if self.model is None:
                raise RuntimeError("Base model not loaded")
            self.peft_model = get_peft_model(self.model, lora_config)  # type: ignore
            
            # Prepare training data
            train_dataset = self.prepare_training_data(training_data)
            train_dataset = train_dataset.map(self.tokenize_function, batched=True)
            
            # Prepare validation data if provided
            eval_dataset = None
            if validation_data:
                eval_dataset = self.prepare_training_data(validation_data)
                eval_dataset = eval_dataset.map(self.tokenize_function, batched=True)
            
            # Set up training arguments
            training_args = TrainingArguments(
                output_dir=str(self.finetuned_model_path),
                num_train_epochs=epochs,
                per_device_train_batch_size=batch_size,
                per_device_eval_batch_size=batch_size,
                warmup_steps=100,
                weight_decay=0.01,
                logging_dir=str(self.finetuned_model_path / "logs"),
                logging_steps=10,
                eval_strategy="epoch" if eval_dataset else "no",
                save_strategy="epoch",
                save_total_limit=2,
                load_best_model_at_end=True if eval_dataset else False,
                metric_for_best_model="eval_loss" if eval_dataset else None,
                greater_is_better=False if eval_dataset else None,
                fp16=torch.cuda.is_available(),
                dataloader_pin_memory=False,
                remove_unused_columns=False
            )
            
            # Set up data collator
            data_collator = DataCollatorForLanguageModeling(
                tokenizer=self.tokenizer,
                mlm=False
            )
            
            # Initialize trainer
            trainer = Trainer(
                model=self.peft_model,
                args=training_args,
                train_dataset=train_dataset,
                eval_dataset=eval_dataset,
                data_collator=data_collator
            )
            
            # Train the model
            logger.info("Starting fine-tuning...")
            trainer.train()
            
            # Save the fine-tuned model
            model_save_path = self.finetuned_model_path / "cybersentinel-tinyllama-lora"
            trainer.save_model(str(model_save_path))
            self.tokenizer.save_pretrained(str(model_save_path))
            
            # Save training configuration
            config = {
                "model_name": self.model_name,
                "lora_config": lora_config.to_dict(),
                "training_args": training_args.to_dict(),
                "training_samples": len(training_data),
                "validation_samples": len(validation_data) if validation_data else 0,
                "epochs": epochs,
                "batch_size": batch_size
            }
            
            with open(model_save_path / "training_config.json", "w") as f:
                json.dump(config, f, indent=2)
            
            logger.info(f"Fine-tuned model saved to {model_save_path}")
            return str(model_save_path)
            
        except Exception as e:
            logger.error(f"Fine-tuning failed: {e}")
            raise
    
    def load_finetuned_model(self, model_path: str):
        """Load a fine-tuned model"""
        try:
            model_path_obj = Path(model_path)
            
            if not model_path_obj.exists():
                raise FileNotFoundError(f"Model path not found: {model_path}")
            
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(str(model_path_obj))
            
            # Load base model
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                torch_dtype=torch.float16,
                device_map="auto" if torch.cuda.is_available() else None
            )
            
            # Load LoRA weights
            self.peft_model = get_peft_model(self.model, LoraConfig.from_pretrained(str(model_path_obj)))  # type: ignore
            self.peft_model.load_state_dict(torch.load(model_path_obj / "adapter_model.bin"))
            
            logger.info(f"Fine-tuned model loaded from {model_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load fine-tuned model: {e}")
            return False
    
    def generate_response(self, prompt: str, max_length: int = 200) -> str:
        """Generate response using fine-tuned model"""
        try:
            if self.peft_model is None:
                raise RuntimeError("No fine-tuned model loaded")
            
            if self.tokenizer is None:
                raise RuntimeError("Tokenizer not loaded")
            
            # Tokenize input
            inputs = self.tokenizer(prompt, return_tensors="pt")
            
            # Generate response
            with torch.no_grad():
                outputs = self.peft_model.generate(
                    **inputs,
                    max_length=max_length,
                    num_return_sequences=1,
                    temperature=0.7,
                    do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            
            # Decode response
            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # Remove input prompt from response
            response = response[len(prompt):].strip()
            
            return response
            
        except Exception as e:
            logger.error(f"Generation failed: {e}")
            return f"Error: {str(e)}"
    
    def evaluate_model(self, test_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate fine-tuned model performance"""
        try:
            if self.peft_model is None:
                raise RuntimeError("No fine-tuned model loaded")
            
            correct_predictions = 0
            total_predictions = len(test_data)
            
            for item in test_data:
                # Create test prompt
                prompt = f"""Analyze this cybersecurity threat:

Title: {item.get('title', 'N/A')}
Description: {item.get('description', 'N/A')}
Source: {item.get('source', 'N/A')}

Provide the threat type and severity:"""
                
                # Generate response
                response = self.generate_response(prompt)
                
                # Simple evaluation (in practice, you'd use more sophisticated metrics)
                expected_type = item.get('threat_type', '').lower()
                expected_severity = item.get('severity', '').lower()
                
                if expected_type in response.lower() and expected_severity in response.lower():
                    correct_predictions += 1
            
            accuracy = correct_predictions / total_predictions if total_predictions > 0 else 0
            
            return {
                "accuracy": accuracy,
                "correct_predictions": correct_predictions,
                "total_predictions": total_predictions,
                "model_path": str(self.finetuned_model_path)
            }
            
        except Exception as e:
            logger.error(f"Evaluation failed: {e}")
            return {"error": str(e)}

# Global fine-tuner instance
fine_tuner = TinyLlamaFineTuner() 