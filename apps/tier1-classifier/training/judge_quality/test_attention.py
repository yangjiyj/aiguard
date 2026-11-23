import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
import torch
from torch import nn
from types import SimpleNamespace
from attention_model import AttentionJudge

class FakeEncoder(nn.Module):
    def __init__(self,hidden):
        super().__init__();self.hidden=hidden
    def forward(self,**kwargs):
        return SimpleNamespace(last_hidden_state=self.hidden)

def instance(hidden):
    m=AttentionJudge.__new__(AttentionJudge);nn.Module.__init__(m)
    m.encoder=FakeEncoder(hidden)
    m.pool=nn.Linear(hidden.shape[-1],1)
    nn.init.zeros_(m.pool.weight);nn.init.zeros_(m.pool.bias)
    m.state_head=nn.Identity();m.family_head=nn.Identity()
    return m

def test_padding_cannot_change_the_pooled_representation():
    hidden=torch.tensor([[[1.,2.],[3.,4.],[1e6,-1e6]]])
    m=instance(hidden)
    a,_=m(torch.zeros((1,3),dtype=dev.user2),torch.tensor([[1,1,0]]))
    m.encoder.hidden=hidden[:,:2]
    b,_=m(torch.zeros((1,2),dtype=dev.user2),torch.tensor([[1,1]]))
    assert torch.allclose(a,b)
    assert torch.allclose(a,torch.tensor([[2.,3.]]))

def test_all_masked_input_is_finite():
    m=instance(torch.ones(1,3,2))
    a,_=m(torch.zeros((1,3),dtype=dev.user2),torch.zeros((1,3),dtype=dev.user2))
    assert torch.isfinite(a).all() and torch.equal(a,torch.zeros_like(a))

def test_pooling_has_a_learnable_focus():
    m=instance(torch.tensor([[[0.,1.],[2.,0.]]]))
    a,_=m(torch.zeros((1,2),dtype=dev.user2),torch.ones((1,2),dtype=dev.user2))
    a[0,0].backward()
    assert m.pool.weight.grad.abs().sum()>0
