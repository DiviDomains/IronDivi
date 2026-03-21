// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Multi-wallet manager
//!
//! Provides thread-safe management of multiple wallets, including loading,
//! unloading, and accessing wallets by name.

use crate::error::WalletError;
use crate::hd::HdWallet;
use crate::wallet_db::WalletDb;
use crate::Network;
use divi_primitives::ChainMode;

use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info};

/// Multi-wallet manager
///
/// Manages multiple loaded wallets, providing thread-safe access
/// and operations like loading/unloading wallets.
pub struct WalletManager {
    /// Loaded wallets indexed by name
    wallets: RwLock<HashMap<String, Arc<WalletDb>>>,
    /// Name of the default wallet (first loaded or explicitly set)
    default_wallet: RwLock<Option<String>>,
    /// Base data directory for wallet files
    data_dir: PathBuf,
    /// Network for all wallets
    network: Network,
}

impl WalletManager {
    /// Create a new wallet manager
    ///
    /// # Arguments
    /// * `data_dir` - Base directory where wallet files are stored
    /// * `network` - Network type for all wallets
    pub fn new(data_dir: PathBuf, network: Network) -> Self {
        WalletManager {
            wallets: RwLock::new(HashMap::new()),
            default_wallet: RwLock::new(None),
            data_dir,
            network,
        }
    }

    /// Get the wallet data directory
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Get the network
    pub fn network(&self) -> Network {
        self.network
    }

    /// Resolve a wallet name to its file path
    fn wallet_path(&self, name: &str) -> PathBuf {
        let wallet_dir = self.data_dir.join("wallets");
        if name == "wallet" || name == "wallet.dat" {
            // Default wallet in root data dir
            self.data_dir.join("wallet.dat")
        } else if name.ends_with(".dat") {
            wallet_dir.join(name)
        } else {
            wallet_dir.join(format!("{}.dat", name))
        }
    }

    /// Normalize wallet name (remove .dat extension for internal tracking)
    fn normalize_name(name: &str) -> String {
        if name.ends_with(".dat") {
            name.trim_end_matches(".dat").to_string()
        } else {
            name.to_string()
        }
    }

    /// Load a wallet from disk
    ///
    /// # Arguments
    /// * `name` - Wallet name (with or without .dat extension)
    ///
    /// # Returns
    /// The loaded wallet wrapped in Arc, or an error if:
    /// - The wallet is already loaded
    /// - The wallet file doesn't exist
    /// - The wallet fails to load
    pub fn load_wallet(&self, name: &str) -> Result<Arc<WalletDb>, WalletError> {
        let normalized_name = Self::normalize_name(name);

        // Check if already loaded
        {
            let wallets = self.wallets.read();
            if wallets.contains_key(&normalized_name) {
                return Err(WalletError::WalletAlreadyLoaded(normalized_name));
            }
        }

        let wallet_path = self.wallet_path(name);

        // Check if wallet file exists
        if !wallet_path.exists() {
            return Err(WalletError::WalletNotFound(normalized_name));
        }

        info!("Loading wallet '{}' from {:?}", normalized_name, wallet_path);

        // Open the wallet
        let wallet = WalletDb::open(&wallet_path, self.network)?;
        let wallet = Arc::new(wallet);

        // Add to loaded wallets
        {
            let mut wallets = self.wallets.write();
            wallets.insert(normalized_name.clone(), Arc::clone(&wallet));
        }

        // Set as default if this is the first wallet
        {
            let mut default = self.default_wallet.write();
            if default.is_none() {
                *default = Some(normalized_name.clone());
                debug!("Set '{}' as default wallet", normalized_name);
            }
        }

        info!("Wallet '{}' loaded successfully", normalized_name);
        Ok(wallet)
    }

    /// Unload a wallet
    ///
    /// # Arguments
    /// * `name` - Wallet name to unload
    ///
    /// # Returns
    /// Ok(()) on success, or an error if the wallet isn't loaded
    pub fn unload_wallet(&self, name: &str) -> Result<(), WalletError> {
        let normalized_name = Self::normalize_name(name);

        // Remove from loaded wallets
        let wallet = {
            let mut wallets = self.wallets.write();
            wallets
                .remove(&normalized_name)
                .ok_or_else(|| WalletError::WalletNotLoaded(normalized_name.clone()))?
        };

        // Save wallet state before unloading
        info!("Saving wallet '{}' before unload", normalized_name);
        wallet.save()?;

        // Update default wallet if needed
        {
            let mut default = self.default_wallet.write();
            if default.as_ref() == Some(&normalized_name) {
                // Pick a new default from remaining wallets
                let wallets = self.wallets.read();
                *default = wallets.keys().next().cloned();
                if let Some(ref new_default) = *default {
                    debug!("New default wallet: '{}'", new_default);
                } else {
                    debug!("No default wallet (all wallets unloaded)");
                }
            }
        }

        info!("Wallet '{}' unloaded successfully", normalized_name);
        Ok(())
    }

    /// Get a wallet by name, or the default wallet if name is None
    ///
    /// # Arguments
    /// * `name` - Optional wallet name. If None, returns the default wallet.
    ///
    /// # Returns
    /// The wallet wrapped in Arc, or an error if not found
    pub fn get_wallet(&self, name: Option<&str>) -> Result<Arc<WalletDb>, WalletError> {
        let wallets = self.wallets.read();

        match name {
            Some(n) => {
                let normalized = Self::normalize_name(n);
                wallets
                    .get(&normalized)
                    .cloned()
                    .ok_or_else(|| WalletError::WalletNotLoaded(normalized))
            }
            None => {
                let default = self.default_wallet.read();
                match default.as_ref() {
                    Some(default_name) => wallets
                        .get(default_name)
                        .cloned()
                        .ok_or_else(|| WalletError::NoDefaultWallet),
                    None => Err(WalletError::NoDefaultWallet),
                }
            }
        }
    }

    /// List all loaded wallet names
    pub fn list_wallets(&self) -> Vec<String> {
        let wallets = self.wallets.read();
        wallets.keys().cloned().collect()
    }

    /// Check if a wallet is loaded
    pub fn is_loaded(&self, name: &str) -> bool {
        let normalized = Self::normalize_name(name);
        self.wallets.read().contains_key(&normalized)
    }

    /// Get the default wallet name
    pub fn default_wallet_name(&self) -> Option<String> {
        self.default_wallet.read().clone()
    }

    /// Set the default wallet
    ///
    /// # Arguments
    /// * `name` - Wallet name to set as default
    ///
    /// # Returns
    /// Ok(()) on success, or an error if the wallet isn't loaded
    pub fn set_default_wallet(&self, name: &str) -> Result<(), WalletError> {
        let normalized = Self::normalize_name(name);

        // Verify wallet is loaded
        {
            let wallets = self.wallets.read();
            if !wallets.contains_key(&normalized) {
                return Err(WalletError::WalletNotLoaded(normalized));
            }
        }

        *self.default_wallet.write() = Some(normalized.clone());
        info!("Default wallet set to '{}'", normalized);
        Ok(())
    }

    /// Create a new wallet
    ///
    /// # Arguments
    /// * `name` - Name for the new wallet
    /// * `mnemonic` - Optional mnemonic. If None, generates a new one.
    ///
    /// # Returns
    /// The created wallet wrapped in Arc
    pub fn create_wallet(
        &self,
        name: &str,
        mnemonic: Option<&str>,
    ) -> Result<Arc<WalletDb>, WalletError> {
        let normalized_name = Self::normalize_name(name);

        // Check if already loaded
        {
            let wallets = self.wallets.read();
            if wallets.contains_key(&normalized_name) {
                return Err(WalletError::WalletAlreadyLoaded(normalized_name));
            }
        }

        let wallet_path = self.wallet_path(name);

        // Check if wallet file already exists
        if wallet_path.exists() {
            return Err(WalletError::WalletAlreadyExists(normalized_name));
        }

        // Ensure parent directory exists
        if let Some(parent) = wallet_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                WalletError::Storage(format!("Failed to create wallet directory: {}", e))
            })?;
        }

        info!(
            "Creating new wallet '{}' at {:?}",
            normalized_name, wallet_path
        );

        // Create HD wallet
        let hd_wallet = match mnemonic {
            Some(m) => HdWallet::from_mnemonic(m, None, ChainMode::Divi)?,
            None => HdWallet::new(ChainMode::Divi)?,
        };

        // Create persistent wallet
        let wallet = WalletDb::create_persistent(&wallet_path, self.network, hd_wallet)?;
        let wallet = Arc::new(wallet);

        // Add to loaded wallets
        {
            let mut wallets = self.wallets.write();
            wallets.insert(normalized_name.clone(), Arc::clone(&wallet));
        }

        // Set as default if this is the first wallet
        {
            let mut default = self.default_wallet.write();
            if default.is_none() {
                *default = Some(normalized_name.clone());
            }
        }

        info!("Wallet '{}' created successfully", normalized_name);
        Ok(wallet)
    }

    /// Get the number of loaded wallets
    pub fn wallet_count(&self) -> usize {
        self.wallets.read().len()
    }

    /// Save all loaded wallets
    pub fn save_all(&self) -> Result<(), WalletError> {
        let wallets = self.wallets.read();
        for (name, wallet) in wallets.iter() {
            debug!("Saving wallet '{}'", name);
            wallet.save()?;
        }
        Ok(())
    }

    /// Shutdown: save and unload all wallets
    pub fn shutdown(&self) -> Result<(), WalletError> {
        info!("Shutting down wallet manager");
        self.save_all()?;

        let mut wallets = self.wallets.write();
        wallets.clear();
        *self.default_wallet.write() = None;

        info!("Wallet manager shutdown complete");
        Ok(())
    }

    /// Add an already-opened wallet to the manager
    ///
    /// This is useful for the initial wallet loaded at startup.
    pub fn add_wallet(&self, name: &str, wallet: Arc<WalletDb>) -> Result<(), WalletError> {
        let normalized_name = Self::normalize_name(name);

        let mut wallets = self.wallets.write();
        if wallets.contains_key(&normalized_name) {
            return Err(WalletError::WalletAlreadyLoaded(normalized_name));
        }

        wallets.insert(normalized_name.clone(), wallet);

        // Set as default if this is the first wallet
        let mut default = self.default_wallet.write();
        if default.is_none() {
            *default = Some(normalized_name.clone());
        }

        info!("Added wallet '{}' to manager", normalized_name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_network() -> Network {
        Network::Regtest
    }

    #[test]
    fn test_wallet_manager_creation() {
        let dir = tempdir().unwrap();
        let manager = WalletManager::new(dir.path().to_path_buf(), test_network());

        assert_eq!(manager.wallet_count(), 0);
        assert!(manager.list_wallets().is_empty());
        assert!(manager.default_wallet_name().is_none());
    }

    #[test]
    fn test_create_and_load_wallet() {
        let dir = tempdir().unwrap();
        let manager = WalletManager::new(dir.path().to_path_buf(), test_network());

        // Create a new wallet
        let wallet = manager.create_wallet("test_wallet", None).unwrap();
        assert!(wallet.mnemonic().is_some());

        // Should be listed
        let wallets = manager.list_wallets();
        assert_eq!(wallets.len(), 1);
        assert!(wallets.contains(&"test_wallet".to_string()));

        // Should be the default
        assert_eq!(
            manager.default_wallet_name(),
            Some("test_wallet".to_string())
        );
    }

    #[test]
    fn test_unload_wallet() {
        let dir = tempdir().unwrap();
        let manager = WalletManager::new(dir.path().to_path_buf(), test_network());

        // Create and unload
        manager.create_wallet("test_wallet", None).unwrap();
        assert_eq!(manager.wallet_count(), 1);

        manager.unload_wallet("test_wallet").unwrap();
        assert_eq!(manager.wallet_count(), 0);
        assert!(!manager.is_loaded("test_wallet"));
    }

    #[test]
    fn test_load_after_unload() {
        let dir = tempdir().unwrap();
        let manager = WalletManager::new(dir.path().to_path_buf(), test_network());

        // Create, generate an address, save
        {
            let wallet = manager.create_wallet("test_wallet", None).unwrap();
            let _addr = wallet.new_receiving_address().unwrap();
            wallet.save().unwrap();
            // wallet reference dropped here
        }

        // Unload (this removes it from the manager, which should be the last Arc reference)
        manager.unload_wallet("test_wallet").unwrap();

        // Reload
        let wallet2 = manager.load_wallet("test_wallet").unwrap();
        assert!(wallet2.mnemonic().is_some());
    }

    #[test]
    fn test_multiple_wallets() {
        let dir = tempdir().unwrap();
        let manager = WalletManager::new(dir.path().to_path_buf(), test_network());

        // Create multiple wallets
        manager.create_wallet("wallet1", None).unwrap();
        manager.create_wallet("wallet2", None).unwrap();
        manager.create_wallet("wallet3", None).unwrap();

        assert_eq!(manager.wallet_count(), 3);

        let wallets = manager.list_wallets();
        assert!(wallets.contains(&"wallet1".to_string()));
        assert!(wallets.contains(&"wallet2".to_string()));
        assert!(wallets.contains(&"wallet3".to_string()));
    }

    #[test]
    fn test_get_wallet_by_name() {
        let dir = tempdir().unwrap();
        let manager = WalletManager::new(dir.path().to_path_buf(), test_network());

        manager.create_wallet("wallet1", None).unwrap();
        manager.create_wallet("wallet2", None).unwrap();

        // Get specific wallet
        let w1 = manager.get_wallet(Some("wallet1")).unwrap();
        let w2 = manager.get_wallet(Some("wallet2")).unwrap();

        // They should be different wallets (different mnemonics)
        assert_ne!(w1.mnemonic(), w2.mnemonic());
    }

    #[test]
    fn test_default_wallet() {
        let dir = tempdir().unwrap();
        let manager = WalletManager::new(dir.path().to_path_buf(), test_network());

        manager.create_wallet("wallet1", None).unwrap();
        manager.create_wallet("wallet2", None).unwrap();

        // First wallet should be default
        assert_eq!(manager.default_wallet_name(), Some("wallet1".to_string()));

        // Get default wallet (None = default)
        let default = manager.get_wallet(None).unwrap();
        let wallet1 = manager.get_wallet(Some("wallet1")).unwrap();
        assert_eq!(default.mnemonic(), wallet1.mnemonic());

        // Change default
        manager.set_default_wallet("wallet2").unwrap();
        assert_eq!(manager.default_wallet_name(), Some("wallet2".to_string()));
    }

    #[test]
    fn test_wallet_not_found() {
        let dir = tempdir().unwrap();
        let manager = WalletManager::new(dir.path().to_path_buf(), test_network());

        let result = manager.load_wallet("nonexistent");
        assert!(matches!(result, Err(WalletError::WalletNotFound(_))));
    }

    #[test]
    fn test_wallet_already_loaded() {
        let dir = tempdir().unwrap();
        let manager = WalletManager::new(dir.path().to_path_buf(), test_network());

        manager.create_wallet("test_wallet", None).unwrap();

        // Try to load again
        let result = manager.load_wallet("test_wallet");
        assert!(matches!(result, Err(WalletError::WalletAlreadyLoaded(_))));
    }

    #[test]
    fn test_wallet_name_normalization() {
        let dir = tempdir().unwrap();
        let manager = WalletManager::new(dir.path().to_path_buf(), test_network());

        // Create with .dat extension
        manager.create_wallet("test.dat", None).unwrap();

        // Should be accessible with or without .dat
        assert!(manager.is_loaded("test"));
        assert!(manager.is_loaded("test.dat"));

        // Both should return the same wallet
        let w1 = manager.get_wallet(Some("test")).unwrap();
        let w2 = manager.get_wallet(Some("test.dat")).unwrap();
        assert_eq!(w1.mnemonic(), w2.mnemonic());
    }

    #[test]
    fn test_save_all() {
        let dir = tempdir().unwrap();
        let manager = WalletManager::new(dir.path().to_path_buf(), test_network());

        manager.create_wallet("wallet1", None).unwrap();
        manager.create_wallet("wallet2", None).unwrap();

        // Should not panic
        manager.save_all().unwrap();
    }

    #[test]
    fn test_shutdown() {
        let dir = tempdir().unwrap();
        let manager = WalletManager::new(dir.path().to_path_buf(), test_network());

        manager.create_wallet("wallet1", None).unwrap();
        manager.create_wallet("wallet2", None).unwrap();

        manager.shutdown().unwrap();

        assert_eq!(manager.wallet_count(), 0);
        assert!(manager.default_wallet_name().is_none());
    }
}
