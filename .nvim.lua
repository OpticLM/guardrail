local current_target_index = 1
local TARGETS = {
  "x86_64-unknown-linux-gnu",
  "x86_64-pc-windows-gnu",
  "aarch64-apple-darwin",
}

vim.api.nvim_create_user_command('RustRotateTarget', function()
  local get_clients = vim.lsp.get_clients or vim.lsp.get_active_clients
  local clients = get_clients({ name = "rust_analyzer" })

  if #clients == 0 then
    vim.notify("No running rust-analyzer", vim.log.levels.WARN)
    return
  end

  local client = clients[1]
  local settings = client.config.settings or {}

  current_target_index = current_target_index % #TARGETS + 1
  local new_target = TARGETS[current_target_index]
  settings["rust-analyzer"] = settings["rust-analyzer"] or {}
  settings["rust-analyzer"].cargo = settings["rust-analyzer"].cargo or {}
  settings["rust-analyzer"].cargo.target = new_target

  client:notify("workspace/didChangeConfiguration", { settings = settings })
  vim.notify("Rust-Analyzer target changed to: " .. new_target, vim.log.levels.INFO)
end, {})

vim.keymap.set('n', '<leader>rr', ':RustRotateTarget<CR>', { desc = "Rotate Rust Target OS", silent = true })
