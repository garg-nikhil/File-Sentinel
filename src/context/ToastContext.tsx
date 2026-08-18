import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import { ToastNotification, ToastType } from '../types';

interface ToastContextType {
  toasts: ToastNotification[];
  notificationHistory: ToastNotification[];
  showToast: (options: Omit<ToastNotification, 'id' | 'timestamp'> & { id?: string }) => string;
  dismissToast: (id: string) => void;
  clearAllToasts: () => void;
  markAllAsRead: () => void;
  clearHistory: () => void;
  unreadCount: number;
  isTrayOpen: boolean;
  setIsTrayOpen: (open: boolean) => void;
}

const ToastContext = createContext<ToastContextType | undefined>(undefined);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<ToastNotification[]>([]);
  const [notificationHistory, setNotificationHistory] = useState<ToastNotification[]>([]);
  const [isTrayOpen, setIsTrayOpen] = useState(false);

  // Play subtle audio alert for security violations & completions
  const playAlertSound = (type: ToastType) => {
    try {
      const AudioContext = window.AudioContext || (window as any).webkitAudioContext;
      if (!AudioContext) return;
      const ctx = new AudioContext();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);

      if (type === 'violation') {
        // Double warning beep
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(600, ctx.currentTime);
        osc.frequency.setValueAtTime(300, ctx.currentTime + 0.15);
        gain.gain.setValueAtTime(0.08, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.3);
      } else if (type === 'success') {
        // High ascending chime
        osc.type = 'sine';
        osc.frequency.setValueAtTime(523.25, ctx.currentTime); // C5
        osc.frequency.setValueAtTime(659.25, ctx.currentTime + 0.1); // E5
        gain.gain.setValueAtTime(0.06, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.25);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.25);
      }
    } catch {
      // Ignore audio autoplay policies if audio context is blocked
    }
  };

  const showToast = useCallback(
    (options: Omit<ToastNotification, 'id' | 'timestamp'> & { id?: string }) => {
      const id = options.id || `toast-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;
      const timestamp = new Date().toISOString();
      const defaultDuration = options.type === 'violation' ? 10000 : options.type === 'warning' ? 8000 : 6000;
      const duration = options.duration ?? defaultDuration;

      const newToast: ToastNotification = {
        id,
        title: options.title,
        message: options.message,
        type: options.type,
        timestamp,
        scanId: options.scanId,
        fileId: options.fileId,
        filePath: options.filePath,
        read: false,
        actionLabel: options.actionLabel,
        onAction: options.onAction,
        duration
      };

      playAlertSound(options.type);

      // Add to active floating toasts
      setToasts(prev => {
        // Prevent duplicate toasts with identical title + message
        if (prev.some(t => t.title === options.title && t.message === options.message)) {
          return prev;
        }
        return [newToast, ...prev].slice(0, 5); // keep max 5 active floating toasts
      });

      // Add to permanent notification history tray
      setNotificationHistory(prev => [newToast, ...prev].slice(0, 50));

      // Auto dismiss from floating toasts after duration
      if (duration !== Infinity) {
        setTimeout(() => {
          dismissToast(id);
        }, duration);
      }

      return id;
    },
    []
  );

  const dismissToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const clearAllToasts = useCallback(() => {
    setToasts([]);
  }, []);

  const markAllAsRead = useCallback(() => {
    setNotificationHistory(prev => prev.map(n => ({ ...n, read: true })));
  }, []);

  const clearHistory = useCallback(() => {
    setNotificationHistory([]);
  }, []);

  const unreadCount = notificationHistory.filter(n => !n.read).length;

  return (
    <ToastContext.Provider
      value={{
        toasts,
        notificationHistory,
        showToast,
        dismissToast,
        clearAllToasts,
        markAllAsRead,
        clearHistory,
        unreadCount,
        isTrayOpen,
        setIsTrayOpen
      }}
    >
      {children}
    </ToastContext.Provider>
  );
};

export const useToast = () => {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
};
