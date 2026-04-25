import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE || '',
  timeout: 30000,
})

export interface ImageRecord {
  id: number
  name: string
  path: string
  os_type: string
  arch: string
  status: 'pending' | 'running' | 'done' | 'error'
  created_at: string
  finished_at: string | null
  result_path: string | null
  error_msg: string | null
}

export const listImages = () =>
  api.get<ImageRecord[]>('/api/images').then(r => r.data)

export const getImage = (id: number) =>
  api.get<ImageRecord>(`/api/images/${id}`).then(r => r.data)

export const uploadImage = (file: File, osType: string) => {
  const form = new FormData()
  form.append('file', file)
  form.append('os_type', osType)
  return api.post<ImageRecord>('/api/images/upload', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }).then(r => r.data)
}

export const reanalyze = (id: number) =>
  api.post(`/api/images/${id}/reanalyze`).then(r => r.data)

export const deleteImage = (id: number) =>
  api.delete(`/api/images/${id}`).then(r => r.data)

export const getResult = (id: number) =>
  api.get(`/api/images/${id}/result`).then(r => r.data)
