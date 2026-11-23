export type ModelMetadata = { model_name?: string; model_label?: string }

export const modelDisplayLabel = (modelName: string, models: ModelMetadata[]) =>
  models.find(model => model.model_name === modelName && model.model_label?.trim())?.model_label?.trim() || modelName
