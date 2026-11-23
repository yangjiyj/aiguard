-- 专用集成凭据档位；存量模型限制继续拦截，防泄漏默认记录。
ALTER TABLE internal_keys
 ADD COLUMN model_enforcement text NOT NULL DEFAULT 'block' CHECK (model_enforcement IN ('record','block')),
 ADD COLUMN dlp_enforcement text NOT NULL DEFAULT 'record' CHECK (dlp_enforcement IN ('record','block')),
 ADD COLUMN model_restriction text NOT NULL DEFAULT '';
