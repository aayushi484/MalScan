import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import DashboardLayout from './components/DashboardLayout';
import NeumorphicCard from './components/NeumorphicCard';
import NeumorphicButton from './components/NeumorphicButton';
import NeumorphicInput from './components/NeumorphicInput';

function App() {
  const [powerMode, setPowerMode] = useState(false);
  const [shieldStatus, setShieldStatus] = useState(true);
  const [warpSpeed, setWarpSpeed] = useState('');

  return (
    <DashboardLayout>
      <div className="flex flex-col md:flex-row gap-12">
        {/* Left Sidebar / Quick Actions */}
        <div className="flex md:flex-col gap-6 items-center justify-center">
          <NeumorphicButton isIcon isActive={powerMode} onClick={() => setPowerMode(!powerMode)}>
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </NeumorphicButton>
          
          <NeumorphicButton isIcon colorVariant="mint" isActive={shieldStatus} onClick={() => setShieldStatus(!shieldStatus)}>
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </NeumorphicButton>
          
          <NeumorphicButton isIcon>
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
          </NeumorphicButton>
        </div>

        {/* Main Content Area */}
        <div className="flex-1 space-y-12">
          {/* Header */}
          <motion.div 
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center justify-between"
          >
            <div>
              <h1 className="text-4xl font-bold tracking-tight text-gray-800">MalScan</h1>
              <p className="text-gray-500 mt-2 font-medium">Zero-G Control Interface</p>
            </div>
          </motion.div>

          {/* Zero-G Control Panel */}
          <NeumorphicCard className="space-y-8 relative overflow-hidden">
            {/* Status Indicator */}
            <div className="flex items-center space-x-4">
              <div className="relative flex h-4 w-4">
                <AnimatePresence>
                  {powerMode && (
                    <motion.span 
                      initial={{ scale: 0 }} animate={{ scale: 1 }} exit={{ scale: 0 }}
                      className="animate-ping absolute inline-flex h-full w-full rounded-full bg-neo-accent-blue opacity-75"
                    />
                  )}
                </AnimatePresence>
                <span className={`relative inline-flex rounded-full h-4 w-4 ${powerMode ? 'bg-neo-accent-blue' : 'bg-gray-400'}`}></span>
              </div>
              <h2 className="text-2xl font-semibold text-gray-700">Flight Telemetry</h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div className="space-y-4">
                <label className="block text-sm font-semibold text-gray-500 uppercase tracking-wider">Target Destination</label>
                <NeumorphicInput placeholder="Enter coordinates..." />
              </div>

              <div className="space-y-4">
                <label className="block text-sm font-semibold text-gray-500 uppercase tracking-wider">Warp Capacity</label>
                <NeumorphicInput 
                  type="number" 
                  placeholder="MACH factor"
                  value={warpSpeed}
                  onChange={(e) => setWarpSpeed(e.target.value)}
                />
              </div>
            </div>

            <div className="pt-6 flex flex-wrap gap-6 border-t border-white/40">
              <NeumorphicButton 
                isActive={powerMode} 
                onClick={() => setPowerMode(!powerMode)}
              >
                {powerMode ? 'System Online' : 'Initialize Drive'}
              </NeumorphicButton>
              <NeumorphicButton 
                colorVariant="mint"
                isActive={shieldStatus} 
                onClick={() => setShieldStatus(!shieldStatus)}
              >
                {shieldStatus ? 'Shields Active' : 'Raise Shields'}
              </NeumorphicButton>
            </div>
          </NeumorphicCard>

          {/* Secondary Stats */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {['Hull Integrity', 'Core Temp', 'Graviton Flux'].map((stat, i) => (
              <NeumorphicCard key={i} padding="p-6" className="text-center">
                <p className="text-gray-500 text-sm font-semibold uppercase tracking-wider mb-2">{stat}</p>
                <p className="text-3xl font-bold text-gray-700">
                  {i === 0 ? '100%' : i === 1 ? '48°C' : 'Stable'}
                </p>
              </NeumorphicCard>
            ))}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}

export default App;
