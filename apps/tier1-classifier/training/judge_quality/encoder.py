"""Existing encoder architecture; training examples must be planned without truncation."""
import torch
import torch.nn as nn
from transformers import AutoModel
STATES=("confirmed_attack","benign_context","uncertain")
FAMILIES=("injection","jailbreak","instruction_override","exfil_intent","other_attack","none")

class Stage2Encoder(nn.Module):
    def __init__(self, snapshot, train_last_layers=0):
        super().__init__()
        self.encoder = AutoModel.from_pretrained(snapshot, local_files_only=True)
        hidden = self.encoder.config.hidden_size
        for param in self.encoder.parameters():
            param.requires_grad = False
        if train_last_layers:
            layers = self.encoder.encoder.layer
            for layer in layers[-train_last_layers:]:
                for param in layer.parameters():
                    param.requires_grad = True
        self.state_head = nn.Linear(hidden, len(STATES))
        self.family_head = nn.Linear(hidden, len(FAMILIES))

    def forward(self, input_ids, attention_mask):
        out = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        hidden = out.last_hidden_state
        mask = attention_mask.unsqueeze(-1).to(hidden.dtype)
        pooled = (hidden * mask).sum(1) / mask.sum(1).clamp(min=1e-6)
        return self.state_head(pooled), self.family_head(pooled)
