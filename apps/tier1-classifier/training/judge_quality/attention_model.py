import torch
import torch.nn as nn
from encoder import Stage2Encoder

class AttentionJudge(Stage2Encoder):
    """Learn to pool contextual token states rather than dilute them uniformly."""
    def __init__(self,snapshot,train_last_layers=6):
        super().__init__(snapshot,train_last_layers)
        h=self.encoder.config.hidden_size
        self.pool=nn.Sequential(nn.Linear(h,128),nn.Tanh(),nn.Linear(128,1))
        nn.init.zeros_(self.pool[-1].weight);nn.init.zeros_(self.pool[-1].bias)

    def forward(self,input_ids,attention_mask):
        hidden=self.encoder(input_ids=input_ids,attention_mask=attention_mask).last_hidden_state
        scores=self.pool(hidden).squeeze(-1).float()
        valid=attention_mask.bool()
        weights=torch.softmax(scores.masked_fill(~valid,-1e9),dim=1)*valid
        weights=weights/weights.sum(1,keepdim=True).clamp_min(1e-9)
        pooled=(hidden*weights.to(hidden.dtype).unsqueeze(-1)).sum(1)
        return self.state_head(pooled),self.family_head(pooled)
