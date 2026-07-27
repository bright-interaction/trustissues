import { NavLink } from 'react-router-dom';
import {
  Activity,
  KeyRound,
  Lock,
  LogOut,
  Settings,
  Users,
} from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import clsx from 'clsx';

type NavItem = {
  to: string;
  icon: typeof Lock;
  label: string;
  adminOnly?: boolean;
};

const navItems: NavItem[] = [
  { to: '/vault', icon: Lock, label: 'Vault' },
  // GET /api/activity is wrapped in AdminOnly, so a non-admin who followed this
  // link just got a failing query and an empty page.
  { to: '/activity', icon: Activity, label: 'Activity', adminOnly: true },
  { to: '/users', icon: Users, label: 'Users', adminOnly: true },
  { to: '/settings', icon: Settings, label: 'Settings' },
];

export default function Sidebar() {
  const { user, isAdmin, isVaultOnly, logout } = useAuth();

  // vault_only keeps a minimal nav, but Settings has to be reachable: it is the
  // only place to mint the browser-extension API key, which is the whole point
  // of the role.
  const items = isVaultOnly
    ? navItems.filter((item) => item.to === '/vault' || item.to === '/settings')
    : navItems.filter((item) => !item.adminOnly || isAdmin);

  return (
    <aside className="fixed inset-y-0 left-0 z-30 flex w-56 flex-col border-r border-slate-200 bg-white">
      <div className="flex h-14 items-center gap-2 border-b border-slate-200 px-4">
        <KeyRound className="h-5 w-5 text-slate-700" />
        <span className="text-base font-semibold text-slate-900">
          Trustissues
        </span>
      </div>

      <nav className="flex-1 space-y-0.5 overflow-y-auto px-2 py-3">
        {items.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-slate-100 text-slate-900'
                  : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
              )
            }
          >
            <item.icon className="h-4 w-4" />
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-slate-200 p-3">
        <div className="mb-2 truncate px-3 text-xs text-slate-500">
          {user?.email}
        </div>
        <button
          onClick={logout}
          className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-medium text-slate-600 transition-colors hover:bg-slate-50 hover:text-slate-900"
        >
          <LogOut className="h-4 w-4" />
          Sign out
        </button>
      </div>
    </aside>
  );
}
